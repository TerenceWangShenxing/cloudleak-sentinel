#!/usr/bin/env python3
"""Create synthetic Docker/APK/mini-program artifacts for a safe competition demo."""
import io
import json
import tarfile
import zipfile
from pathlib import Path
import sys

out = Path(sys.argv[1] if len(sys.argv) > 1 else 'demo_artifacts').expanduser().resolve()
out.mkdir(parents=True, exist_ok=True)

# Local text/config artifact.
(out/'demo-local.env').write_text(
    'password=LocalSynthetic_Q7m2X9p4K8v3N6s1\n'
    'client_secret=LocalOAuth_R8v1N6s3D5f0H2j7\n',
    encoding='utf-8',
)


# Docker-save compatible image TAR with a secret in config.Env and a layer file.
layer_buf = io.BytesIO()
with tarfile.open(fileobj=layer_buf, mode='w') as layer:
    data = b'password=ContainerSecret_Q7m2X9p4K8v3N6s1\n'
    info = tarfile.TarInfo('app/.env'); info.size = len(data)
    layer.addfile(info, io.BytesIO(data))
layer_bytes = layer_buf.getvalue()
manifest = json.dumps([{'Config':'config.json','RepoTags':['cloudleak-demo:latest'],'Layers':['layer.tar']}]).encode()
config = json.dumps({'config':{'Env':['API_KEY=ContainerKey_R8v1N6s3D5f0H2j7']}}).encode()
with tarfile.open(out/'demo-image.tar', 'w') as t:
    for name, data in [('manifest.json', manifest), ('config.json', config), ('layer.tar', layer_bytes)]:
        info = tarfile.TarInfo(name); info.size = len(data); t.addfile(info, io.BytesIO(data))

# APK-like ZIP: text asset + DEX printable string.
with zipfile.ZipFile(out/'demo-app.apk', 'w', zipfile.ZIP_DEFLATED) as z:
    z.writestr('assets/config.json', json.dumps({'client_secret':'MobileSecret_Q7m2X9p4K8v3N6s1D5f0'}))
    z.writestr('classes.dex', b'\x00\x01password=EmbeddedDex_R8v1N6s3D5f0H2j7\x00\x00')

# Mini-program ZIP with common project files.
with zipfile.ZipFile(out/'demo-miniprogram.zip', 'w', zipfile.ZIP_DEFLATED) as z:
    z.writestr('app.json', '{"pages":["pages/index/index"]}')
    z.writestr('app.js', 'const api_key = "MiniProgramKey_Q7m2X9p4K8v3N6s1";')
    z.writestr('project.config.json', '{"description":"synthetic CloudLeak demo"}')

print(out)
print(out/'demo-image.tar')
print(out/'demo-app.apk')
print(out/'demo-miniprogram.zip')
