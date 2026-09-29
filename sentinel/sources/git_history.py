from pathlib import Path
import re
import subprocess
from datetime import datetime, timezone
from typing import Iterable

from .base import SourceAdapter
from ..models import Artifact

_DIFF_FILE = re.compile(r'^diff --git a/(.*?) b/(.*?)$')


class LocalGitHistorySource(SourceAdapter):
    """Scan an explicitly selected local Git repository and model secret lifecycle.

    Patches are processed chronologically. Added lines are normal findings; removed lines are
    emitted as lifecycle-only artifacts so the engine can close an exposure without creating
    a duplicate risk event. Nothing is executed from the repository.
    """

    channel = 'git-history'

    def __init__(self, path: str, max_commits: int = 100):
        self.path = Path(path).expanduser().resolve()
        self.max_commits = min(max(int(max_commits), 1), 1000)
        if not self.path.exists():
            raise ValueError('Path does not exist')
        if not (self.path / '.git').exists():
            try:
                root = subprocess.check_output(
                    ['git', '-C', str(self.path), 'rev-parse', '--show-toplevel'],
                    stderr=subprocess.DEVNULL,
                    text=True,
                    timeout=5,
                ).strip()
                self.path = Path(root).resolve()
            except Exception as e:
                raise ValueError('Path is not a Git working tree') from e

    def _run(self, args: list[str]) -> str:
        return subprocess.check_output(
            ['git', '-C', str(self.path), *args],
            stderr=subprocess.DEVNULL,
            text=True,
            errors='ignore',
            timeout=20,
        )

    @staticmethod
    def _split_patch(patch: str):
        current = '(unknown)'
        added: dict[str, list[str]] = {}
        removed: dict[str, list[str]] = {}
        for line in patch.splitlines():
            m = _DIFF_FILE.match(line)
            if m:
                current = m.group(2)
                continue
            if line.startswith('+++') or line.startswith('---'):
                continue
            if line.startswith('+'):
                added.setdefault(current, []).append(line[1:])
            elif line.startswith('-'):
                removed.setdefault(current, []).append(line[1:])
        return added, removed

    def collect(self) -> Iterable[Artifact]:
        observed = datetime.now(timezone.utc).isoformat()
        revs = self._run(['rev-list', '--all', f'--max-count={self.max_commits}']).splitlines()
        # rev-list is newest-first. Lifecycle needs exposure -> removal ordering.
        revs = list(reversed([x.strip() for x in revs if x.strip()]))
        scope = f'git:{self.path}'
        for sha in revs:
            try:
                published = self._run(['show', '-s', '--format=%cI', sha]).strip() or None
                patch = self._run([
                    'show', '--no-ext-diff', '--format=', '--unified=0',
                    '--find-renames', '--find-copies', sha, '--'
                ])
            except Exception:
                continue
            if not patch.strip():
                continue
            added, removed = self._split_patch(patch)
            for path, lines in added.items():
                content = '\n'.join(lines).strip()
                if not content:
                    continue
                yield Artifact(
                    source='local-git-history', channel='git-history',
                    locator=f'git://{self.path}@{sha[:12]}:{path}',
                    content=content, observed_at=observed, published_at=published,
                    metadata={
                        'repo_path': str(self.path), 'scope': scope, 'sha': sha,
                        'path': path, 'history': True, 'git_change': 'added',
                    },
                )
            for path, lines in removed.items():
                content = '\n'.join(lines).strip()
                if not content:
                    continue
                yield Artifact(
                    source='local-git-history', channel='git-history',
                    locator=f'git://{self.path}@{sha[:12]}:{path}',
                    content=content, observed_at=observed, published_at=published,
                    metadata={
                        'repo_path': str(self.path), 'scope': scope, 'sha': sha,
                        'path': path, 'history': True, 'git_change': 'removed',
                        'lifecycle_only': True,
                    },
                )
