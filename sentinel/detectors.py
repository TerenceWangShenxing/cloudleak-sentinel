import re
from dataclasses import dataclass
from typing import List

from .models import Artifact, Finding
from .risk import assess
from .timeutil import latency_ms
from .utils import shannon_entropy, fingerprint, mask, context_score


@dataclass
class Rule:
    name: str
    pattern: re.Pattern
    base: float
    severity: str
    entropy_min: float = 0.0
    group: int = 0


RULES: List[Rule] = [
    Rule('AWS Access Key ID', re.compile(r'\b(?:AKIA|ASIA)[A-Z0-9]{16}\b'), 0.96, 'medium'),
    Rule('Alibaba Cloud AccessKey ID', re.compile(r'\bLTAI[A-Za-z0-9]{12,24}\b'), 0.94, 'medium'),
    Rule('Tencent Cloud SecretId', re.compile(r'\bAKID[A-Za-z0-9]{28,48}\b'), 0.94, 'medium'),
    Rule('SSH Private Key', re.compile(r'-----BEGIN (?:OPENSSH|RSA|EC|DSA) PRIVATE KEY-----'), 1.00, 'critical'),
    Rule('PEM Private Key', re.compile(r'-----BEGIN PRIVATE KEY-----'), 1.00, 'critical'),
    Rule('GitHub Token', re.compile(r'\bgh[pousr]_[A-Za-z0-9_]{30,255}\b'), 0.98, 'critical', 3.0),
    Rule('Slack-style Token', re.compile(r'\bxox[baprs]-[A-Za-z0-9-]{10,200}\b'), 0.96, 'high', 3.0),
    Rule('JWT', re.compile(r'\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b'), 0.72, 'medium', 3.0),
    Rule('Database URI', re.compile(r'(?i)\b(?:mysql|postgres(?:ql)?|mongodb(?:\+srv)?|redis)://[^:/@\s\'"<>]{1,80}:[^@\s\'"<>]{3,200}\@[^\s\'"<>]{3,250}\b'), 0.88, 'high'),
    Rule('OAuth Client Secret', re.compile(
        r'''(?ix)\b(?:oauth[_-]?)?client[_-]?secret["\']?\s*[:=]\s*["']?([A-Za-z0-9_./+=:@-]{8,200})["']?'''
    ), 0.82, 'high', 2.7, 1),
    Rule('Generic Secret Assignment', re.compile(
        r'''(?ix)\b(?:api[_-]?key|secret(?:[_-]?key)?|password|passwd|pwd|token)["\']?\s*[:=]\s*["']?([A-Za-z0-9_./+=:@-]{8,200})["']?'''
    ), 0.64, 'high', 2.7, 1),
]

PAIR_RULES = [
    (
        'Huawei Cloud AK/SK Pair',
        re.compile(r'''(?ix)\b(?:HUAWEI(?:_CLOUD)?|HWC)[_-]?(?:ACCESS[_-]?KEY|AK)["\']?\s*[:=]\s*["']?([A-Z0-9]{16,32})["']?'''),
        re.compile(r'''(?ix)\b(?:HUAWEI(?:_CLOUD)?|HWC)[_-]?(?:SECRET[_-]?KEY|SK)["\']?\s*[:=]\s*["']?([A-Za-z0-9/+_=.-]{24,80})["']?'''),
    ),
    (
        'AWS AK/SK Pair',
        re.compile(r'''(?ix)\bAWS[_-]?(?:ACCESS[_-]?KEY[_-]?ID|ACCESS[_-]?KEY|AK)["\']?\s*[:=]\s*["']?((?:AKIA|ASIA)[A-Z0-9]{16})["']?'''),
        re.compile(r'''(?ix)\bAWS[_-]?(?:SECRET[_-]?ACCESS[_-]?KEY|SECRET[_-]?KEY|SK)["\']?\s*[:=]\s*["']?([A-Za-z0-9/+=]{32,64})["']?'''),
    ),
    (
        'Alibaba Cloud AK/SK Pair',
        re.compile(r'''(?ix)\b(?:ALIYUN|ALIBABA(?:_CLOUD)?)[_-]?(?:ACCESS[_-]?KEY[_-]?ID|AK)["\']?\s*[:=]\s*["']?(LTAI[A-Za-z0-9]{12,24})["']?'''),
        re.compile(r'''(?ix)\b(?:ALIYUN|ALIBABA(?:_CLOUD)?)[_-]?(?:ACCESS[_-]?KEY[_-]?SECRET|SK)["\']?\s*[:=]\s*["']?([A-Za-z0-9/+_=.-]{24,80})["']?'''),
    ),
    (
        'Tencent Cloud SecretId/SecretKey Pair',
        re.compile(r'''(?ix)\b(?:TENCENT(?:_CLOUD)?)[_-]?(?:SECRET[_-]?ID|AK)["\']?\s*[:=]\s*["']?(AKID[A-Za-z0-9]{28,48})["']?'''),
        re.compile(r'''(?ix)\b(?:TENCENT(?:_CLOUD)?)[_-]?(?:SECRET[_-]?KEY|SK)["\']?\s*[:=]\s*["']?([A-Za-z0-9/+_=.-]{24,80})["']?'''),
    ),
]

PLACEHOLDER_WORDS = re.compile(r'(?i)(example|sample|dummy|placeholder|changeme|your[_-]?key|not[_-]?real|test[_-]?only)')


def _exposure_state(artifact: Artifact) -> str:
    return 'history' if (artifact.metadata or {}).get('history') else 'current'


def _make_finding(artifact: Artifact, kind: str, secret: str, score: float, entropy: float,
                  start: int, end: int, reason: str, extra_evidence=None):
    placeholder = bool(PLACEHOLDER_WORDS.search(secret))
    has_context = context_score(artifact.content, start, end) > 0
    state = _exposure_state(artifact)
    rr = assess(
        credential_type=kind,
        confidence=score,
        entropy=entropy,
        locator=artifact.locator,
        has_context=has_context,
        placeholder=placeholder,
        exposure_state=state,
        extra_evidence=extra_evidence,
    )
    if placeholder:
        reason += '; placeholder/test marker observed'
    return Finding(
        source=artifact.source,
        locator=artifact.locator,
        credential_type=kind,
        masked_value=mask(secret),
        fingerprint=fingerprint(secret),
        confidence=round(score, 3),
        severity=rr.severity,
        reason=reason,
        observed_at=artifact.observed_at,
        published_at=artifact.published_at,
        channel=artifact.channel or artifact.source,
        detection_latency_ms=latency_ms(artifact.published_at, artifact.observed_at),
        risk_score=rr.score,
        evidence=rr.evidence,
        exposure_state=state,
    )


def detect(artifact: Artifact) -> List[Finding]:
    out: List[Finding] = []
    text = artifact.content

    for name, ak_re, sk_re in PAIR_RULES:
        ak = ak_re.search(text)
        sk = sk_re.search(text)
        if ak and sk:
            ak_val, sk_val = ak.group(1), sk.group(1)
            combined = f'{name}|{ak_val}|{sk_val}'
            ent = (shannon_entropy(ak_val) + shannon_entropy(sk_val)) / 2
            placeholder = bool(PLACEHOLDER_WORDS.search(combined))
            state = _exposure_state(artifact)
            rr = assess(
                credential_type=name,
                confidence=0.995,
                entropy=ent,
                locator=artifact.locator,
                has_context=True,
                placeholder=placeholder,
                exposure_state=state,
                extra_evidence=['AK 与 SK 在同一对象内完成关联'],
            )
            reason = 'provider-specific access-key and secret-key fields co-occurred in the same artifact'
            if placeholder:
                reason += '; placeholder/test marker observed'
            out.append(Finding(
                source=artifact.source,
                locator=artifact.locator,
                credential_type=name,
                masked_value=f'AK={mask(ak_val)} / SK={mask(sk_val)}',
                fingerprint=fingerprint(combined),
                confidence=0.995,
                severity=rr.severity,
                reason=reason,
                observed_at=artifact.observed_at,
                published_at=artifact.published_at,
                channel=artifact.channel or artifact.source,
                detection_latency_ms=latency_ms(artifact.published_at, artifact.observed_at),
                risk_score=rr.score,
                evidence=rr.evidence,
                exposure_state=state,
            ))

    for rule in RULES:
        for m in rule.pattern.finditer(text):
            secret = m.group(rule.group) if rule.group else m.group(0)
            ent = shannon_entropy(secret)
            if ent < rule.entropy_min:
                continue
            ctx_bonus = context_score(text, m.start(), m.end())
            score = min(1.0, rule.base + ctx_bonus)
            out.append(_make_finding(
                artifact, rule.name, secret, score, ent, m.start(), m.end(),
                f'rule={rule.name}; entropy={ent:.2f}',
            ))

    unique = {}
    for f in out:
        unique[(f.fingerprint, f.credential_type)] = f
    return list(unique.values())


def rule_catalog():
    names = [r.name for r in RULES] + [x[0] for x in PAIR_RULES]
    return sorted(set(names))
