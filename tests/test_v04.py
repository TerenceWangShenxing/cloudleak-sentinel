from pathlib import Path
import tempfile

from sentinel.models import Artifact
from sentinel.detectors import detect
from sentinel.risk import assess
from sentinel.db import init


def test_risk_pair_is_high_or_critical():
    ak = 'AB12' + 'CD34EF56GH78IJ90'
    sk = 'X9q7' + 'Lm4P2vN8rT6sK5w3Z1y8B4c6D0f2'
    text = f'HUAWEI_CLOUD_AK={ak}\nHUAWEI_CLOUD_SK={sk}'
    a = Artifact('test','/srv/prod/.env',text,'2026-01-01T00:00:10+00:00')
    pair = [x for x in detect(a) if x.credential_type == 'Huawei Cloud AK/SK Pair'][0]
    assert pair.risk_score >= 70
    assert pair.severity in {'high','critical'}
    assert pair.evidence


def test_history_state():
    a = Artifact('git','git:///tmp/repo@abc','password=HistorySecret_Q9x7L4m2N8p6','2026-01-01T00:00:10+00:00',
                 '2026-01-01T00:00:00+00:00','git-history',{'history': True})
    f = detect(a)[0]
    assert f.exposure_state == 'history'
    assert f.detection_latency_ms == 10000.0


def test_placeholder_reduces_risk():
    real = assess(credential_type='Generic Secret Assignment', confidence=.79, entropy=4.2,
                  locator='/srv/prod/.env', has_context=True, placeholder=False)
    demo = assess(credential_type='Generic Secret Assignment', confidence=.79, entropy=4.2,
                  locator='/examples/demo.env', has_context=True, placeholder=True)
    assert real.score > demo.score
