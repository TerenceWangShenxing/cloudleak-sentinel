from sentinel.models import Artifact
from sentinel.detectors import detect
from sentinel.timeutil import latency_ms
from sentinel.plugins import catalog


def test_generic_secret():
    a = Artifact('test','mem','password=RealisticQ9x7L4m2N8p6','2026-01-01T00:00:10+00:00')
    names = {x.credential_type for x in detect(a)}
    assert 'Generic Secret Assignment' in names


def test_huawei_pair():
    ak = 'AB12' + 'CD34EF56GH78IJ90'
    sk = 'X9q7' + 'Lm4P2vN8rT6sK5w3Z1y8B4c6D0f2'
    text = f'HUAWEI_CLOUD_AK={ak}\nHUAWEI_CLOUD_SK={sk}'
    a = Artifact('test','mem',text,'2026-01-01T00:00:10+00:00')
    names = {x.credential_type for x in detect(a)}
    assert 'Huawei Cloud AK/SK Pair' in names


def test_latency():
    assert latency_ms('2026-01-01T00:00:00Z','2026-01-01T00:00:01.500+00:00') == 1500.0


def test_plugins():
    ids = {x['id'] for x in catalog()}
    assert 'github-monitor' in ids
    assert 'gitee-repo' in ids
