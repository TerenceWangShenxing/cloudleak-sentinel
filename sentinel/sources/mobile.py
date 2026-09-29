import re
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from .base import SourceAdapter
from ..models import Artifact

MAX_ENTRY = 4 * 1024 * 1024
TEXT_EXTS = {
    '.txt','.md','.js','.json','.xml','.html','.css','.yaml','.yml','.ini','.conf','.properties',
    '.wxml','.wxss','.ts','.java','.kt','.swift','.plist','.env'
}
ASCII_STRINGS = re.compile(rb'[ -~]{8,}')
UTF16LE_STRINGS = re.compile(rb'(?:[ -~]\x00){8,}')


def _extract_strings(data: bytes, limit=8000) -> str:
    out = []
    for m in ASCII_STRINGS.finditer(data):
        out.append(m.group(0).decode('ascii', errors='ignore'))
        if len(out) >= limit:
            break
    if len(out) < limit:
        for m in UTF16LE_STRINGS.finditer(data):
            try:
                out.append(m.group(0).decode('utf-16le', errors='ignore'))
            except Exception:
                pass
            if len(out) >= limit:
                break
    return '\n'.join(out)


def _interesting(name: str) -> bool:
    low = name.lower()
    return any(low.endswith(x) for x in TEXT_EXTS) or any(
        x in low for x in ('classes.dex','resources.arsc','assets/','res/raw/','app-config','project.config')
    )


class MobilePackageSource(SourceAdapter):
    """Static scanner for APK, mini-program bundles/directories and ZIP packages.

    It never installs or executes the application. Text assets are decoded directly; bounded
    printable-string extraction is used for DEX/resources/wxapkg binaries.
    """

    channel = 'mobile-package'

    def __init__(self, path: str):
        self.path = Path(path).expanduser().resolve()
        if not self.path.exists():
            raise ValueError('Package path does not exist')

    def _artifact(self, locator, text, observed, package_type, entry):
        return Artifact(
            source='mobile-package', channel=package_type, locator=locator, content=text,
            observed_at=observed, metadata={'package_type': package_type, 'path': entry},
        )

    def collect(self) -> Iterable[Artifact]:
        observed = datetime.now(timezone.utc).isoformat()
        if self.path.is_dir():
            package_type = 'mini-program'
            for p in self.path.rglob('*'):
                if not p.is_file() or p.stat().st_size > MAX_ENTRY:
                    continue
                rel = str(p.relative_to(self.path))
                if not _interesting(rel):
                    continue
                data = p.read_bytes()
                text = data.decode('utf-8', errors='ignore') if b'\x00' not in data[:1024] else _extract_strings(data)
                if text:
                    yield self._artifact(f'mini://{self.path.name}/{rel}', text, observed, package_type, rel)
            return

        suffix = self.path.suffix.lower()
        package_type = 'apk' if suffix == '.apk' else ('mini-program' if suffix == '.wxapkg' else 'app-archive')
        if suffix in {'.apk', '.zip'} or zipfile.is_zipfile(self.path):
            with zipfile.ZipFile(self.path) as z:
                if suffix == '.zip':
                    names = {x.filename.lower().lstrip('./') for x in z.infolist()}
                    if 'app.json' in names or 'project.config.json' in names or any(x.endswith('.wxml') for x in names):
                        package_type = 'mini-program'
                for info in z.infolist():
                    if info.is_dir() or info.file_size <= 0 or info.file_size > MAX_ENTRY or not _interesting(info.filename):
                        continue
                    try:
                        data = z.read(info)
                    except Exception:
                        continue
                    if any(info.filename.lower().endswith(x) for x in TEXT_EXTS) and b'\x00' not in data[:1024]:
                        text = data.decode('utf-8', errors='ignore')
                    else:
                        text = _extract_strings(data)
                    if text:
                        yield self._artifact(
                            f'{package_type}://{self.path.name}/{info.filename}', text, observed, package_type, info.filename
                        )
            return

        # Raw wxapkg / unknown app binary: bounded printable-string extraction.
        data = self.path.read_bytes()[:MAX_ENTRY]
        text = _extract_strings(data)
        if text:
            yield self._artifact(f'{package_type}://{self.path.name}', text, observed, package_type, self.path.name)
