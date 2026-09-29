import io
import json
import tarfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from .base import SourceAdapter
from ..models import Artifact

MAX_MEMBER = 2 * 1024 * 1024
MAX_LAYER = 96 * 1024 * 1024
TEXT_EXTS = {
    '.txt','.md','.py','.js','.ts','.java','.go','.rs','.c','.cpp','.h','.json','.yaml','.yml',
    '.toml','.ini','.conf','.env','.xml','.html','.properties','.sh','.ps1','.gradle','.kt','.swift','.sql'
}


def _looks_text_path(name: str) -> bool:
    low = name.lower()
    base = Path(low).name
    return any(low.endswith(x) for x in TEXT_EXTS) or base.startswith('.env') or any(
        token in low for token in ('/config/', '/secrets/', '/credentials/', '/.aws/', '/.kube/')
    )


def _text_from_bytes(data: bytes) -> str | None:
    if not data:
        return None
    if b'\x00' not in data[:1024]:
        return data.decode('utf-8', errors='ignore')
    # Pull printable strings from binaries/config blobs without executing them.
    chunks = []
    cur = bytearray()
    for b in data:
        if 32 <= b <= 126 or b in (9, 10, 13):
            cur.append(b)
        else:
            if len(cur) >= 8:
                chunks.append(bytes(cur))
            cur.clear()
    if len(cur) >= 8:
        chunks.append(bytes(cur))
    if not chunks:
        return None
    return '\n'.join(x.decode('ascii', errors='ignore') for x in chunks[:5000])


class DockerImageTarSource(SourceAdapter):
    """Deep static scan of a Docker/OCI image exported as a local TAR.

    Supports Docker `save` layout (manifest.json + nested layer.tar) and falls back to a normal
    TAR walk. Earlier layer content is intentionally visible because deleted secrets remain in
    image history/layers.
    """

    channel = 'docker-image'

    def __init__(self, path: str):
        self.path = Path(path).expanduser().resolve()
        if not self.path.is_file():
            raise ValueError('Docker image TAR does not exist')

    def _artifact(self, locator, content, observed, metadata):
        return Artifact(
            source='docker-image', channel='docker-image', locator=locator,
            content=content, observed_at=observed, metadata=metadata,
        )

    def collect(self) -> Iterable[Artifact]:
        observed = datetime.now(timezone.utc).isoformat()
        with tarfile.open(self.path, 'r:*') as outer:
            names = set(outer.getnames())
            if 'manifest.json' in names:
                mf = outer.extractfile('manifest.json')
                manifest = json.loads((mf.read() if mf else b'[]').decode('utf-8', errors='ignore') or '[]')
                for image_idx, entry in enumerate(manifest):
                    config_name = entry.get('Config')
                    tags = entry.get('RepoTags') or []
                    image_name = tags[0] if tags else f'image-{image_idx}'
                    if config_name in names:
                        cf = outer.extractfile(config_name)
                        if cf:
                            try:
                                cfg = json.loads(cf.read().decode('utf-8', errors='ignore'))
                                envs = (((cfg.get('config') or {}).get('Env')) or [])
                                if envs:
                                    yield self._artifact(
                                        f'docker://{self.path.name}/{image_name}/config:Env', '\n'.join(envs), observed,
                                        {'image': image_name, 'container_config': True, 'path': 'config.Env'},
                                    )
                            except Exception:
                                pass
                    layers = entry.get('Layers') or []
                    for idx, layer_name in enumerate(layers):
                        member = outer.getmember(layer_name) if layer_name in names else None
                        if not member or member.size > MAX_LAYER:
                            continue
                        lf = outer.extractfile(member)
                        if not lf:
                            continue
                        try:
                            layer_bytes = lf.read(MAX_LAYER + 1)
                            if len(layer_bytes) > MAX_LAYER:
                                continue
                            with tarfile.open(fileobj=io.BytesIO(layer_bytes), mode='r:*') as layer:
                                for fm in layer.getmembers():
                                    if not fm.isfile() or fm.size <= 0 or fm.size > MAX_MEMBER:
                                        continue
                                    if not _looks_text_path(fm.name) and fm.size > 512 * 1024:
                                        continue
                                    ff = layer.extractfile(fm)
                                    if not ff:
                                        continue
                                    data = ff.read(MAX_MEMBER + 1)
                                    if len(data) > MAX_MEMBER:
                                        continue
                                    text = _text_from_bytes(data)
                                    if not text:
                                        continue
                                    yield self._artifact(
                                        f'docker://{self.path.name}/{image_name}/layer/{idx}:{fm.name}', text, observed,
                                        {
                                            'image': image_name, 'layer_index': idx, 'layer_count': len(layers),
                                            'path': fm.name, 'history': True, 'container_layer': True,
                                        },
                                    )
                        except tarfile.TarError:
                            continue
                return

            # Generic TAR fallback.
            for m in outer.getmembers():
                if not m.isfile() or m.size <= 0 or m.size > MAX_MEMBER:
                    continue
                f = outer.extractfile(m)
                if not f:
                    continue
                data = f.read(MAX_MEMBER + 1)
                if len(data) > MAX_MEMBER:
                    continue
                text = _text_from_bytes(data)
                if text:
                    yield self._artifact(
                        f'docker://{self.path.name}/tar:{m.name}', text, observed,
                        {'path': m.name, 'history': True, 'container_layer': True},
                    )
