import os
import threading
import time
from pathlib import Path
from typing import Optional

from .db import (
    claim_next_job, create_job, finish_job, reset_interrupted_jobs,
    update_job_progress,
)
from .engine import run
from .sources.filesystem import FileSystemSource
from .sources.url import PublicURLSource
from .sources.wiki import PublicWikiPageSource
from .sources.github import GitHubRepoSource
from .sources.gitee import GiteeRepoSource
from .sources.git_history import LocalGitHistorySource
from .sources.docker_image import DockerImageTarSource
from .sources.mobile import MobilePackageSource

_stop = threading.Event()
_threads: list[threading.Thread] = []


def enqueue(kind: str, target: str, payload: dict | None = None) -> int:
    return create_job(kind, target, payload or {})


def _source_for(job):
    kind = job['kind']
    p = job.get('payload') or {}
    target = job['target']
    if kind == 'local':
        path = Path(target).expanduser()
        if not path.exists():
            raise ValueError('Path does not exist')
        return FileSystemSource(str(path)), str(path), True
    if kind == 'git-history':
        src = LocalGitHistorySource(target, int(p.get('max_commits', 100)))
        return src, f'{src.path} [lifecycle]', False
    if kind == 'docker':
        src = DockerImageTarSource(target)
        return src, str(src.path), True
    if kind == 'mobile':
        src = MobilePackageSource(target)
        return src, str(src.path), True
    if kind == 'url':
        return PublicURLSource(target), target, True
    if kind == 'wiki':
        return PublicWikiPageSource(target), target, True
    if kind == 'github':
        return GitHubRepoSource(target, p.get('ref'), int(p.get('max_files', 200))), target, True
    if kind == 'gitee':
        return GiteeRepoSource(target, p.get('ref'), min(int(p.get('max_files', 150)), 500)), target, True
    raise ValueError(f'Unsupported job kind: {kind}')


def _execute(job):
    last = {'processed': 0, 'matches': 0, 'new_findings': 0, 'suppressed': 0, 'skipped_unchanged': 0, 'duration_ms': 0}

    def progress(s):
        last.update(s)
        update_job_progress(
            job['id'], processed=s.get('processed'), matches=s.get('matches'),
            new_findings=s.get('new_findings'), suppressed=s.get('suppressed'),
            skipped_unchanged=s.get('skipped_unchanged')
        )

    try:
        src, label, incremental = _source_for(job)
        findings, new_count, artifacts, duration_ms, suppressed = run(
            src, label, incremental=incremental, progress=progress
        )
        finish_job(
            job['id'], status='done', processed=artifacts, matches=len(findings),
            new_findings=new_count, suppressed=suppressed,
            skipped_unchanged=last.get('skipped_unchanged', 0), duration_ms=duration_ms
        )
    except Exception as e:
        finish_job(
            job['id'], status='error', processed=last.get('processed', 0),
            matches=last.get('matches', 0), new_findings=last.get('new_findings', 0),
            suppressed=last.get('suppressed', 0), skipped_unchanged=last.get('skipped_unchanged', 0),
            duration_ms=last.get('duration_ms', 0), error=f'{type(e).__name__}: {e}'
        )


def _loop(worker_id: int):
    while not _stop.is_set():
        job = claim_next_job()
        if job:
            _execute(job)
            continue
        _stop.wait(0.35)


def start():
    global _threads
    if any(t.is_alive() for t in _threads):
        return
    reset_interrupted_jobs()
    _stop.clear()
    n = max(1, min(4, int(os.getenv('CLOUDLEAK_WORKERS', '2'))))
    _threads = []
    for i in range(n):
        t = threading.Thread(target=_loop, args=(i,), name=f'cloudleak-job-{i}', daemon=True)
        t.start(); _threads.append(t)


def stop():
    _stop.set()
    for t in list(_threads):
        t.join(timeout=1.0)
