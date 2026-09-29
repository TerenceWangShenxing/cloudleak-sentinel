import base64
import os
from datetime import datetime, timezone
from typing import Iterable, Optional
import requests

from .base import SourceAdapter
from ..models import Artifact

API = 'https://gitee.com/api/v5'
MAX_FILE = 1024 * 1024
TEXT_EXTS = {'.txt','.md','.py','.js','.ts','.java','.go','.rs','.c','.cpp','.h','.json','.yaml','.yml','.toml','.ini','.conf','.env','.xml','.html','.properties','.sh','.ps1','.gradle','.kt','.swift','.sql'}


def _repo_name(repo: str) -> str:
    value = repo.strip().strip('/')
    if value.startswith('https://gitee.com/'):
        value = value[len('https://gitee.com/'):]
    if value.endswith('.git'):
        value = value[:-4]
    parts = value.split('/')
    if len(parts) != 2 or not all(parts):
        raise ValueError('Gitee repository must be owner/repo')
    return value


def _params(extra=None):
    p = dict(extra or {})
    token = os.getenv('GITEE_TOKEN', '').strip()
    if token:
        p['access_token'] = token
    return p


class GiteeRepoSource(SourceAdapter):
    channel = 'gitee'

    def __init__(self, repo: str, ref: Optional[str] = None, max_files: int = 200):
        self.repo = _repo_name(repo)
        self.ref = ref or 'master'
        self.max_files = min(max(int(max_files), 1), 500)

    def _walk(self, path=''):
        r = requests.get(f'{API}/repos/{self.repo}/contents/{path}', params=_params({'ref':self.ref}), timeout=15)
        if r.status_code == 404 and not path:
            # Some repositories default to main; let the caller override ref if needed.
            r.raise_for_status()
        r.raise_for_status()
        data = r.json()
        if isinstance(data, dict):
            data = [data]
        for item in data:
            yield item

    def collect(self) -> Iterable[Artifact]:
        # Repository-scoped recursive walk. No site-wide code search.
        observed = datetime.now(timezone.utc).isoformat()
        queue = ['']
        emitted = 0
        while queue and emitted < self.max_files:
            path = queue.pop(0)
            for item in self._walk(path):
                typ = item.get('type')
                ipath = item.get('path') or item.get('name') or ''
                if typ == 'dir':
                    queue.append(ipath)
                    continue
                if typ != 'file':
                    continue
                low = ipath.lower()
                if not (any(low.endswith(x) for x in TEXT_EXTS) or low.endswith('.env')):
                    continue
                detail = requests.get(f'{API}/repos/{self.repo}/contents/{ipath}', params=_params({'ref':self.ref}), timeout=12)
                if not detail.ok:
                    continue
                d = detail.json()
                if d.get('encoding') != 'base64':
                    continue
                try:
                    raw = base64.b64decode(d.get('content',''))
                except Exception:
                    continue
                if len(raw) > MAX_FILE:
                    continue
                emitted += 1
                yield Artifact(
                    source='gitee-repo', channel='gitee',
                    locator=f'https://gitee.com/{self.repo}/blob/{self.ref}/{ipath}',
                    content=raw.decode('utf-8', errors='ignore'), observed_at=observed,
                    metadata={'repo':self.repo,'ref':self.ref,'path':ipath},
                )
                if emitted >= self.max_files:
                    return
