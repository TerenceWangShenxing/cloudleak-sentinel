import io
import json
import os
import subprocess
import tarfile
import zipfile
from pathlib import Path

from sentinel.benchmark import run_benchmark
from sentinel.detectors import detect
from sentinel.models import Artifact
from sentinel.sources.docker_image import DockerImageTarSource
from sentinel.sources.git_history import LocalGitHistorySource
from sentinel.sources.mobile import MobilePackageSource


def test_benchmark_regression():
    r = run_benchmark()
    assert r['cases'] >= 20
    assert r['recall'] >= 0.9
    assert r['precision'] >= 0.9
    assert r['f1'] >= 0.9


def test_git_history_marks_removal(tmp_path):
    repo = tmp_path / 'repo'; repo.mkdir()
    subprocess.check_call(['git','init','-q',str(repo)])
    subprocess.check_call(['git','-C',str(repo),'config','user.email','demo@example.invalid'])
    subprocess.check_call(['git','-C',str(repo),'config','user.name','CloudLeak Demo'])
    f = repo / 'config.env'
    ak = 'AB12' + 'CD34EF56GH78IJ90'
    sk = 'X9q7' + 'M2k4R8v1N6s3D5f0H2j7L4c8'
    f.write_text(f'HUAWEI_ACCESS_KEY={ak}\nHUAWEI_SECRET_KEY={sk}\n')
    subprocess.check_call(['git','-C',str(repo),'add','.']); subprocess.check_call(['git','-C',str(repo),'commit','-qm','add'])
    f.write_text('# cleaned\n')
    subprocess.check_call(['git','-C',str(repo),'add','.']); subprocess.check_call(['git','-C',str(repo),'commit','-qm','remove'])
    arts = list(LocalGitHistorySource(str(repo), 10).collect())
    assert any((a.metadata or {}).get('git_change') == 'added' for a in arts)
    assert any((a.metadata or {}).get('git_change') == 'removed' for a in arts)
    added = [a for a in arts if (a.metadata or {}).get('git_change') == 'added']
    removed = [a for a in arts if (a.metadata or {}).get('git_change') == 'removed']
    assert any(any(x.credential_type == 'Huawei Cloud AK/SK Pair' for x in detect(a)) for a in added)
    assert any(any(x.credential_type == 'Huawei Cloud AK/SK Pair' for x in detect(a)) for a in removed)


def _tar_bytes(files):
    bio = io.BytesIO()
    with tarfile.open(fileobj=bio, mode='w') as t:
        for name, data in files.items():
            b = data.encode()
            info = tarfile.TarInfo(name); info.size = len(b)
            t.addfile(info, io.BytesIO(b))
    return bio.getvalue()


def test_docker_save_layer_scan(tmp_path):
    layer = _tar_bytes({'app/.env':'password=Q7m2X9p4K8v3N6s1\n'})
    p = tmp_path/'image.tar'
    with tarfile.open(p, 'w') as out:
        manifest = json.dumps([{'Config':'config.json','RepoTags':['demo:latest'],'Layers':['layer.tar']}]).encode()
        info=tarfile.TarInfo('manifest.json'); info.size=len(manifest); out.addfile(info,io.BytesIO(manifest))
        cfg=json.dumps({'config':{'Env':['API_KEY=R8v1N6s3D5f0H2j7']}}).encode()
        info=tarfile.TarInfo('config.json'); info.size=len(cfg); out.addfile(info,io.BytesIO(cfg))
        info=tarfile.TarInfo('layer.tar'); info.size=len(layer); out.addfile(info,io.BytesIO(layer))
    arts=list(DockerImageTarSource(str(p)).collect())
    assert any('config:Env' in a.locator for a in arts)
    assert any('app/.env' in a.locator for a in arts)
    assert sum(len(detect(a)) for a in arts) >= 2


def test_apk_binary_string_scan(tmp_path):
    p=tmp_path/'demo.apk'
    with zipfile.ZipFile(p,'w') as z:
        z.writestr('assets/config.json','{"client_secret":"Q7m2X9p4K8v3N6s1D5f0H2j7"}')
        z.writestr('classes.dex',b'\x00\x01password=R8v1N6s3D5f0H2j7\x00more')
    arts=list(MobilePackageSource(str(p)).collect())
    assert any('assets/config.json' in a.locator for a in arts)
    assert any('classes.dex' in a.locator for a in arts)
    assert sum(len(detect(a)) for a in arts) >= 2
