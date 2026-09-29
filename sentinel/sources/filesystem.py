from pathlib import Path
from datetime import datetime, timezone
from typing import Iterable
import tarfile, zipfile
from .base import SourceAdapter
from ..models import Artifact

TEXT_EXTS = {'.txt','.md','.py','.js','.ts','.java','.go','.rs','.c','.cpp','.h','.json','.yaml','.yml','.toml','.ini','.conf','.env','.xml','.html','.properties','.sh','.ps1','.gradle','.kt','.swift','.sql'}
MAX_FILE = 2 * 1024 * 1024


def now():
    return datetime.now(timezone.utc).isoformat()


def artifact_from_bytes(source, locator, data):
    return Artifact(source=source, channel=source, locator=locator,
                    content=data.decode('utf-8', errors='ignore'), observed_at=now())


class FileSystemSource(SourceAdapter):
    channel = 'filesystem'

    def __init__(self, path: str):
        self.path = Path(path)

    def collect(self) -> Iterable[Artifact]:
        if self.path.is_file():
            yield from self._one(self.path)
            return
        for p in self.path.rglob('*'):
            if p.is_file():
                yield from self._one(p)

    def _one(self, p: Path):
        try:
            if p.stat().st_size > MAX_FILE:
                return
            if p.suffix.lower() in TEXT_EXTS or p.name.startswith('.env'):
                yield artifact_from_bytes('filesystem', str(p), p.read_bytes())
            elif p.suffix.lower() in {'.zip', '.apk'}:
                with zipfile.ZipFile(p) as z:
                    for info in z.infolist():
                        if info.file_size <= MAX_FILE:
                            try:
                                data = z.read(info)
                                if b'\x00' not in data[:512]:
                                    yield artifact_from_bytes('archive', f'{p}!{info.filename}', data)
                            except Exception:
                                pass
            elif p.suffix.lower() == '.tar':
                with tarfile.open(p) as t:
                    for m in t.getmembers():
                        if m.isfile() and m.size <= MAX_FILE:
                            f = t.extractfile(m)
                            if f:
                                data = f.read()
                                if b'\x00' not in data[:512]:
                                    yield artifact_from_bytes('container-tar', f'{p}!{m.name}', data)
        except Exception:
            return
