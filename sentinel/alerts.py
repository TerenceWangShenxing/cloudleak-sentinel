import json
import os
import requests
from .db import create_alert


def _message(f):
    return {
        'severity': f.severity,
        'credential_type': f.credential_type,
        'masked_value': f.masked_value,
        'source': f.source,
        'channel': f.channel,
        'locator': f.locator,
        'confidence': f.confidence,
        'observed_at': f.observed_at,
        'published_at': f.published_at,
        'detection_latency_ms': f.detection_latency_ms,
        'risk_score': f.risk_score,
        'evidence': f.evidence or [],
        'exposure_state': f.exposure_state,
    }


def emit_alert(finding_id, f):
    if f.severity not in {'critical', 'high'}:
        return None
    payload = _message(f)
    alert_id = create_alert(
        finding_id,
        f.severity,
        f'{f.severity.upper()} · {f.credential_type}',
        json.dumps(payload, ensure_ascii=False),
    )
    hook = os.getenv('CLOUDLEAK_ALERT_WEBHOOK', '').strip()
    if hook:
        try:
            requests.post(hook, json={'event': 'cloudleak.finding', 'data': payload}, timeout=5)
        except Exception:
            pass
    return alert_id
