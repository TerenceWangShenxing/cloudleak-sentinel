import base64
import os
from datetime import datetime, timezone
from typing import Iterable, Optional
import requests

from .base import SourceAdapter
from ..models import Artifact

API = 'https://api.github.com'
MAX_FILE = 1024 * 1024
TEXT_EXTS = {'.txt','.md','.py','.js','.ts','.java','.go','.rs','.c','.cpp','.h','.json','.yaml','.yml','.toml','.ini','.conf','.env','.xml','.html','.properties','.sh','.ps1','.gradle','.kt','.swift','.sql'}


def _headers():
    h = {'Accept': 'application/vnd.github+json', 'User-Agent': 'CloudLeak-Sentinel/0.5 defensive-monitor'}
    token = os.getenv('GITHUB_TOKEN', '').strip()
    if token:
        h['Authorization'] = f'Bearer {token}'
    return h


def _repo_name(repo: str) -> str:
    value = repo.strip().strip('/')
    if value.startswith('https://github.com/'):
        value = value[len('https://github.com/'):]
    if value.endswith('.git'):
        value = value[:-4]
    parts = value.split('/')
    if len(parts) != 2 or not all(parts):
        raise ValueError('GitHub repository must be owner/repo')
    return f'{parts[0]}/{parts[1]}'


def latest_commit(repo: str, branch: Optional[str] = None):
    repo = _repo_name(repo)
    params = {'per_page': 1}
    if branch:
        params['sha'] = branch
    r = requests.get(f'{API}/repos/{repo}/commits', headers=_headers(), params=params, timeout=12)
    r.raise_for_status()
    data = r.json()
    if not data:
        return None
    return data[0]


class GitHubCommitSource(SourceAdapter):
    channel = 'github'

    def __init__(self, repo: str, sha: str):
        self.repo = _repo_name(repo)
        self.sha = sha

    def collect(self) -> Iterable[Artifact]:
        r = requests.get(f'{API}/repos/{self.repo}/commits/{self.sha}', headers=_headers(), timeout=15)
        r.raise_for_status()
        data = r.json()
        published = (data.get('commit', {}).get('committer', {}) or {}).get('date') or (data.get('commit', {}).get('author', {}) or {}).get('date')
        observed = datetime.now(timezone.utc).isoformat()
        for f in data.get('files', [])[:100]:
            filename = f.get('filename', '')
            patch = f.get('patch') or ''
            if patch:
                yield Artifact(
                    source='github-commit-patch', channel='github',
                    locator=f'https://github.com/{self.repo}/commit/{self.sha}#{filename}',
                    content=patch, observed_at=observed, published_at=published,
                    metadata={'repo': self.repo, 'sha': self.sha, 'path': filename},
                )
                continue
            raw_url = f.get('raw_url')
            if raw_url and any(filename.lower().endswith(x) for x in TEXT_EXTS):
                rr = requests.get(raw_url, headers={'User-Agent':'CloudLeak-Sentinel/0.5'}, timeout=10)
                if rr.ok and len(rr.content) <= MAX_FILE:
                    yield Artifact(
                        source='github-file', channel='github',
                        locator=f'https://github.com/{self.repo}/blob/{self.sha}/{filename}',
                        content=rr.text, observed_at=observed, published_at=published,
                        metadata={'repo': self.repo, 'sha': self.sha, 'path': filename},
                    )


class GitHubRepoSource(SourceAdapter):
    channel = 'github'

    def __init__(self, repo: str, ref: Optional[str] = None, max_files: int = 250):
        self.repo = _repo_name(repo)
        self.ref = ref
        self.max_files = min(max(int(max_files), 1), 1000)

    def collect(self) -> Iterable[Artifact]:
        # Repository-scoped scan only. No global code search is performed.
        meta = requests.get(f'{API}/repos/{self.repo}', headers=_headers(), timeout=12)
        meta.raise_for_status()
        default_branch = meta.json().get('default_branch', 'main')
        ref = self.ref or default_branch
        branch = requests.get(f'{API}/repos/{self.repo}/branches/{ref}', headers=_headers(), timeout=12)
        branch.raise_for_status()
        tree_sha = (((branch.json().get('commit') or {}).get('commit') or {}).get('tree') or {}).get('sha')
        if not tree_sha:
            # Fallback: commit SHA also resolves through the tree endpoint on GitHub.
            tree_sha = (branch.json().get('commit') or {}).get('sha')
        tree = requests.get(f'{API}/repos/{self.repo}/git/trees/{tree_sha}', headers=_headers(), params={'recursive':'1'}, timeout=20)
        tree.raise_for_status()
        files = [x for x in tree.json().get('tree', []) if x.get('type') == 'blob']
        observed = datetime.now(timezone.utc).isoformat()
        seen = 0
        for item in files:
            if seen >= self.max_files:
                break
            path = item.get('path','')
            size = int(item.get('size') or 0)
            if size <= 0 or size > MAX_FILE:
                continue
            low = path.lower()
            if not (any(low.endswith(x) for x in TEXT_EXTS) or '/.env' in low or low.endswith('.env')):
                continue
            blob = requests.get(item['url'], headers=_headers(), timeout=10)
            if not blob.ok:
                continue
            b = blob.json()
            if b.get('encoding') != 'base64':
                continue
            try:
                content = base64.b64decode(b.get('content','')).decode('utf-8', errors='ignore')
            except Exception:
                continue
            seen += 1
            yield Artifact(
                source='github-repo', channel='github',
                locator=f'https://github.com/{self.repo}/blob/{ref}/{path}',
                content=content, observed_at=observed,
                metadata={'repo': self.repo, 'ref': ref, 'path': path},
            )
