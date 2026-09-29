import json
import base64
from functools import lru_cache
from pathlib import Path
from .detectors import detect
from .models import Artifact
from .timeutil import utcnow_iso

ROOT = Path(__file__).resolve().parent.parent
CASES = ROOT / 'benchmark' / 'cases.json'
EVAL_CASES = ROOT / 'benchmark' / 'evaluation_cases.json'


def _evaluate(path: Path, dataset: str, *, min_risk: int = 0):
    cases = json.loads(path.read_text(encoding='utf-8'))
    tp = fp = fn = tn = type_hits = positive_cases = 0
    details = []
    now = utcnow_iso()
    for c in cases:
        if 'text_b64' in c:
            content = base64.b64decode(c['text_b64']).decode('utf-8')
        else:
            content = c.get('text', '')
        art = Artifact(source='benchmark', channel='benchmark', locator=f"benchmark://{c['id']}", content=content, observed_at=now)
        raw = detect(art)
        found = [x for x in raw if int(x.risk_score or 0) >= int(min_risk)]
        predicted = sorted({x.credential_type for x in found})
        expected = c.get('expected')
        pos = expected is not None
        pred_pos = bool(found)
        if pos:
            positive_cases += 1
            if pred_pos: tp += 1
            else: fn += 1
            if expected in predicted: type_hits += 1
        else:
            if pred_pos: fp += 1
            else: tn += 1
        details.append({
            'id': c['id'], 'expected': expected, 'predicted': predicted,
            'max_risk': max([x.risk_score for x in raw], default=0),
            'ok': (expected in predicted) if pos else not pred_pos
        })
    precision = tp / (tp + fp) if tp + fp else 1.0
    recall = tp / (tp + fn) if tp + fn else 1.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        'dataset': dataset, 'cases': len(cases), 'positive_cases': positive_cases,
        'tp': tp, 'fp': fp, 'fn': fn, 'tn': tn,
        'precision': round(precision, 4), 'recall': round(recall, 4), 'f1': round(f1, 4),
        'type_hit_rate': round(type_hits / positive_cases, 4) if positive_cases else 1.0,
        'min_risk': int(min_risk), 'details': details,
    }


@lru_cache(maxsize=8)
def run_benchmark(path: str | None = None):
    r = _evaluate(Path(path or CASES), 'synthetic-regression-v0.6', min_risk=0)
    r['note'] = 'Synthetic regression benchmark; used to catch detector regressions, not to claim real-world accuracy.'
    return r


@lru_cache(maxsize=8)
def run_evaluation(path: str | None = None):
    r = _evaluate(Path(path or EVAL_CASES), 'curated-adversarial-v0.6', min_risk=45)
    r['note'] = ('Curated synthetic/adversarial evaluation with near-misses and placeholders. '
                 'Actionable threshold risk>=45. It is still not a real-internet prevalence claim.')
    return r
