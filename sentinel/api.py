from pathlib import Path
import hashlib
import hmac
import json
import os
import tempfile

from fastapi import FastAPI, HTTPException, Request, UploadFile, File
from fastapi.responses import HTMLResponse, StreamingResponse
from pydantic import BaseModel, Field

from .benchmark import run_benchmark, run_evaluation
from .db import (
    all_findings, query_findings, recent_scans, metrics, alerts, acknowledge_alert,
    upsert_monitor, list_monitors, delete_monitor,
    allowlist_from_finding, list_allowlist, delete_allowlist, list_exposures,
    list_jobs, job_by_id,
)
from .detectors import rule_catalog
from .engine import run
from .monitor import start as start_monitor_worker, stop as stop_monitor_worker
from .jobs import start as start_job_workers, stop as stop_job_workers, enqueue
from .health import channel_health
from .plugins import catalog as plugin_catalog
from .sources.filesystem import FileSystemSource
from .sources.url import PublicURLSource
from .sources.wiki import PublicWikiPageSource
from .sources.github import GitHubRepoSource, GitHubCommitSource
from .sources.gitee import GiteeRepoSource
from .sources.git_history import LocalGitHistorySource
from .sources.docker_image import DockerImageTarSource
from .sources.mobile import MobilePackageSource
from .demo import inject as inject_demo
from .experiments import load_or_run as load_experiments, run_final_experiments

app = FastAPI(
    title='CloudLeak Sentinel',
    version='1.0.0',
    description='Defensive cloud-credential exposure detection and response prototype. It never validates or uses discovered credentials.'
)

WEB = Path(__file__).parent / 'web' / 'index.html'
MAX_UPLOAD = 64 * 1024 * 1024


class ScanReq(BaseModel):
    path: str = Field(min_length=1)


class URLScanReq(BaseModel):
    url: str = Field(min_length=8)


class RepoReq(BaseModel):
    repo: str = Field(min_length=3, description='owner/repo')
    ref: str | None = None
    max_files: int = Field(default=200, ge=1, le=1000)


class HistoryReq(BaseModel):
    path: str = Field(min_length=1)
    max_commits: int = Field(default=100, ge=1, le=1000)


class MonitorReq(BaseModel):
    repo: str = Field(min_length=3, description='owner/repo')
    interval_sec: int = Field(default=120, ge=60, le=86400)


class AllowlistReq(BaseModel):
    reason: str = Field(default='manual allowlist', max_length=300)


@app.on_event('startup')
def _startup():
    start_monitor_worker()
    start_job_workers()


@app.on_event('shutdown')
def _shutdown():
    stop_monitor_worker()
    stop_job_workers()


@app.get('/', response_class=HTMLResponse, include_in_schema=False)
def home():
    return WEB.read_text(encoding='utf-8')


@app.get('/health')
def health():
    return {'status': 'ok', 'version': '1.0.0'}


@app.get('/findings')
def findings(limit: int = 200, severity: str | None = None, channel: str | None = None,
             q: str | None = None, min_risk: int = 0, exposure_state: str | None = None):
    return query_findings(
        min(max(limit, 1), 1000), severity=severity, channel=channel, q=q,
        min_risk=max(0, min(100, int(min_risk or 0))), exposure_state=exposure_state
    )


@app.get('/exposures')
def exposures(limit: int = 200):
    return list_exposures(min(max(limit, 1), 1000))


@app.get('/benchmark')
def benchmark():
    return run_benchmark()


@app.get('/evaluation')
def evaluation():
    return run_evaluation()


@app.get('/channel-health')
def get_channel_health():
    return {'channels': channel_health()}


@app.get('/metrics')
def get_metrics():
    m = metrics()
    plugins = plugin_catalog()
    bm = run_benchmark()
    ev = run_evaluation()
    m['credential_rule_count'] = len(rule_catalog())
    m['plugins'] = plugins
    m['implemented_channel_count'] = len({x['id'] for x in plugins if x['status'] in {'ready','beta'}})
    m['benchmark'] = {k: v for k, v in bm.items() if k != 'details'}
    m['evaluation'] = {k: v for k, v in ev.items() if k != 'details'}
    health = channel_health()
    m['channel_health'] = health
    m['healthy_channel_count'] = sum(1 for x in health if x['health'] == 'ready')
    return m


@app.get('/jobs')
def jobs(limit: int = 50, status: str | None = None):
    return list_jobs(min(max(limit, 1), 200), status=status)


@app.get('/jobs/{job_id}')
def get_job(job_id: int):
    x = job_by_id(job_id)
    if not x:
        raise HTTPException(404, 'Job not found')
    return x


def _queued(kind, target, payload=None):
    jid = enqueue(kind, target, payload or {})
    return {'accepted': True, 'job_id': jid, 'kind': kind, 'target': target}


@app.post('/jobs/local')
def queue_local(req: ScanReq):
    p = Path(req.path).expanduser()
    if not p.exists(): raise HTTPException(404, 'Path does not exist')
    return _queued('local', str(p))


@app.post('/jobs/git-history')
def queue_history(req: HistoryReq):
    return _queued('git-history', req.path, {'max_commits': req.max_commits})


@app.post('/jobs/docker')
def queue_docker(req: ScanReq):
    return _queued('docker', req.path)


@app.post('/jobs/mobile')
def queue_mobile(req: ScanReq):
    return _queued('mobile', req.path)


@app.post('/jobs/github')
def queue_github(req: RepoReq):
    return _queued('github', req.repo, {'ref': req.ref, 'max_files': req.max_files})


@app.post('/jobs/gitee')
def queue_gitee(req: RepoReq):
    return _queued('gitee', req.repo, {'ref': req.ref, 'max_files': min(req.max_files, 500)})


@app.post('/jobs/url')
def queue_url(req: URLScanReq):
    return _queued('url', req.url)


@app.post('/jobs/wiki')
def queue_wiki(req: URLScanReq):
    return _queued('wiki', req.url)


@app.get('/report/competition')
def competition_report():
    m = metrics()
    bm = run_benchmark(); ev = run_evaluation(); health = channel_health()
    return {
        'version': '0.6.0',
        'scope': 'defensive explicit-target credential exposure monitoring',
        'metrics': m,
        'regression_benchmark': {k:v for k,v in bm.items() if k != 'details'},
        'curated_evaluation': {k:v for k,v in ev.items() if k != 'details'},
        'channels': health,
        'recent_scans': recent_scans(20),
        'limitations': [
            'Evaluation datasets are synthetic/curated and are not a claim about Internet-wide accuracy.',
            'Connectors are explicit-target or authorized-feed scoped; the tool does not validate or use discovered credentials.',
            'External API rate limits and platform terms apply.'
        ]
    }



class DemoReq(BaseModel):
    scenario: str = Field(default='cloud-pair', pattern='^(cloud-pair|oauth|database|token)$')

@app.post('/demo/inject')
def demo_inject(req: DemoReq):
    found,new_count,artifacts,duration_ms,suppressed=inject_demo(req.scenario)
    return {'ok':True,'synthetic':True,'scenario':req.scenario,'matches':len(found),'new_findings':new_count,
            'artifacts':artifacts,'duration_ms':duration_ms,'suppressed':suppressed}

@app.get('/experiments/summary')
def experiment_summary():
    return load_experiments()

@app.post('/experiments/run')
def experiment_run():
    return run_final_experiments(save=True)

@app.get('/stream')
def stream():
    import time as _time
    def gen():
        for _ in range(3600):
            payload={'metrics':metrics(),'jobs':list_jobs(8),'ts':_time.time()}
            yield 'data: '+json.dumps(payload,ensure_ascii=False)+'\\n\\n'
            _time.sleep(1.0)
    return StreamingResponse(gen(), media_type='text/event-stream', headers={'Cache-Control':'no-cache'})

@app.get('/scans')
def scans(limit: int = 20):
    return recent_scans(min(max(limit, 1), 100))


@app.get('/rules')
def rules():
    return {'count': len(rule_catalog()), 'rules': rule_catalog()}


@app.get('/plugins')
def plugins():
    return {'count': len(plugin_catalog()), 'plugins': plugin_catalog()}


@app.get('/alerts')
def get_alerts(limit: int = 100, unacked_only: bool = False):
    return alerts(min(max(limit, 1), 500), unacked_only)


@app.post('/alerts/{alert_id}/ack')
def ack(alert_id: int):
    if not acknowledge_alert(alert_id):
        raise HTTPException(404, 'Alert not found')
    return {'ok': True}


@app.get('/allowlist')
def get_allowlist():
    return list_allowlist()


@app.post('/allowlist/from-finding/{finding_id}')
def add_to_allowlist(finding_id: int, req: AllowlistReq):
    item_id = allowlist_from_finding(finding_id, req.reason)
    if not item_id:
        raise HTTPException(404, 'Finding not found')
    return {'ok': True, 'id': item_id}


@app.delete('/allowlist/{item_id}')
def remove_allowlist(item_id: int):
    if not delete_allowlist(item_id):
        raise HTTPException(404, 'Allowlist item not found')
    return {'ok': True}


@app.get('/monitors')
def monitors():
    return list_monitors()


@app.post('/monitors/github')
def add_github_monitor(req: MonitorReq):
    mid = upsert_monitor('github-repo', req.repo, max(60, req.interval_sec), True)
    return {'id': mid, 'kind': 'github-repo', 'target': req.repo, 'interval_sec': max(60, req.interval_sec), 'enabled': True}


@app.delete('/monitors/{monitor_id}')
def remove_monitor(monitor_id: int):
    if not delete_monitor(monitor_id):
        raise HTTPException(404, 'Monitor not found')
    return {'ok': True}


def _response(result):
    found, new_count, artifacts, duration_ms, suppressed = result
    return {
        'matches': len(found),
        'new_findings': new_count,
        'suppressed': suppressed,
        'artifacts': artifacts,
        'duration_ms': duration_ms,
        'findings': [x.to_dict() for x in found],
    }


@app.post('/scan')
def scan(req: ScanReq):
    p = Path(req.path).expanduser()
    if not p.exists():
        raise HTTPException(status_code=404, detail='Path does not exist')
    return _response(run(FileSystemSource(str(p)), str(p)))


@app.post('/scan/git-history')
def scan_git_history(req: HistoryReq):
    try:
        src = LocalGitHistorySource(req.path, req.max_commits)
        return _response(run(src, f'{src.path} [lifecycle]'))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except FileNotFoundError:
        raise HTTPException(status_code=500, detail='git executable was not found')
    except Exception as e:
        raise HTTPException(status_code=502, detail=f'Git lifecycle scan failed: {type(e).__name__}: {e}')


@app.post('/scan/docker')
def scan_docker(req: ScanReq):
    try:
        src = DockerImageTarSource(req.path)
        return _response(run(src, str(src.path)))
    except (ValueError, OSError) as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=502, detail=f'Docker image scan failed: {type(e).__name__}: {e}')


@app.post('/scan/mobile')
def scan_mobile(req: ScanReq):
    try:
        src = MobilePackageSource(req.path)
        return _response(run(src, str(src.path)))
    except (ValueError, OSError) as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=502, detail=f'Mobile package scan failed: {type(e).__name__}: {e}')


@app.post('/scan/url')
def scan_url(req: URLScanReq):
    try:
        return _response(run(PublicURLSource(req.url), req.url))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=502, detail=f'Unable to scan URL: {e}')


@app.post('/scan/wiki')
def scan_wiki(req: URLScanReq):
    try:
        return _response(run(PublicWikiPageSource(req.url), req.url))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=502, detail=f'Unable to scan Wiki/knowledge page: {e}')


@app.post('/scan/github')
def scan_github(req: RepoReq):
    try:
        return _response(run(GitHubRepoSource(req.repo, req.ref, req.max_files), req.repo))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=502, detail=f'GitHub scan failed: {type(e).__name__}: {e}')


@app.post('/scan/gitee')
def scan_gitee(req: RepoReq):
    try:
        return _response(run(GiteeRepoSource(req.repo, req.ref, min(req.max_files, 500)), req.repo))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=502, detail=f'Gitee scan failed: {type(e).__name__}: {e}')


def _source_for_uploaded(path: str, filename: str):
    low = filename.lower()
    if low.endswith(('.tar', '.tar.gz', '.tgz')):
        return DockerImageTarSource(path), 'docker-upload'
    if low.endswith(('.apk', '.zip', '.wxapkg')):
        return MobilePackageSource(path), 'mobile-upload'
    raise ValueError('Upload supports .tar/.tar.gz/.tgz/.apk/.zip/.wxapkg only')


@app.post('/scan/upload')
async def scan_upload(file: UploadFile = File(...)):
    filename = Path(file.filename or 'upload.bin').name
    suffix = ''.join(Path(filename).suffixes[-2:]) or Path(filename).suffix
    tmp = tempfile.NamedTemporaryFile(prefix='cloudleak-', suffix=suffix, delete=False)
    tmp_path = tmp.name
    total = 0
    try:
        while True:
            chunk = await file.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_UPLOAD:
                raise HTTPException(413, 'Upload exceeds 64 MiB limit')
            tmp.write(chunk)
        tmp.close()
        src, label = _source_for_uploaded(tmp_path, filename)
        result = _response(run(src, f'upload:{filename}'))
        result['filename'] = filename
        result['upload_bytes'] = total
        result['upload_kind'] = label
        return result
    except HTTPException:
        raise
    except ValueError as e:
        raise HTTPException(400, str(e))
    finally:
        try:
            tmp.close()
        except Exception:
            pass
        try:
            os.unlink(tmp_path)
        except Exception:
            pass


def _verify_github_signature(body: bytes, signature: str | None):
    secret = os.getenv('GITHUB_WEBHOOK_SECRET', '').encode()
    if not secret:
        return True
    if not signature or not signature.startswith('sha256='):
        return False
    expected = 'sha256=' + hmac.new(secret, body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


@app.post('/webhooks/github')
async def github_webhook(request: Request):
    body = await request.body()
    if not _verify_github_signature(body, request.headers.get('X-Hub-Signature-256')):
        raise HTTPException(401, 'Invalid GitHub webhook signature')
    try:
        payload = json.loads(body or b'{}')
    except Exception:
        raise HTTPException(400, 'Invalid JSON')
    repo = (payload.get('repository') or {}).get('full_name')
    sha = payload.get('after') or ((payload.get('head_commit') or {}).get('id'))
    if not repo or not sha or set(sha) == {'0'}:
        return {'accepted': True, 'scanned': False, 'reason': 'no repository/head commit'}
    try:
        result = _response(run(GitHubCommitSource(repo, sha), f'{repo}@{sha}'))
        return {'accepted': True, 'scanned': True, **result}
    except Exception as e:
        raise HTTPException(status_code=502, detail=f'Webhook commit scan failed: {type(e).__name__}: {e}')
