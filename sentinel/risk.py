import re
from dataclasses import dataclass
from typing import Iterable

SENSITIVE_PATH = re.compile(
    r'(?i)(^|[/_.-])(?:\.env|env|secret|secrets|credential|credentials|config|settings|application|'
    r'values|docker|compose|kube|kubernetes|ci|cd|workflow|pipeline|prod|production)(?:[/_.-]|$)'
)
TEST_PATH = re.compile(r'(?i)(^|[/_.-])(?:test|tests|fixture|fixtures|example|examples|sample|samples|demo|mock)(?:[/_.-]|$)')

STRONG_TYPES = {
    'SSH Private Key', 'PEM Private Key', 'GitHub Token', 'Database URI',
    'Huawei Cloud AK/SK Pair', 'AWS AK/SK Pair', 'Alibaba Cloud AK/SK Pair',
    'Tencent Cloud SecretId/SecretKey Pair',
}
PAIR_TYPES = {x for x in STRONG_TYPES if 'Pair' in x}


@dataclass
class RiskResult:
    score: int
    severity: str
    evidence: list[str]


def severity_from_score(score: int) -> str:
    if score >= 90:
        return 'critical'
    if score >= 70:
        return 'high'
    if score >= 45:
        return 'medium'
    return 'low'


def assess(*, credential_type: str, confidence: float, entropy: float, locator: str,
           has_context: bool, placeholder: bool, exposure_state: str = 'current',
           extra_evidence: Iterable[str] | None = None) -> RiskResult:
    # Explainable, bounded heuristic score. It is intentionally deterministic so it can be
    # benchmarked and discussed in a competition report.
    score = int(round(max(0.0, min(1.0, confidence)) * 55))
    evidence: list[str] = [f'规则置信度 {confidence:.0%}']

    if credential_type in STRONG_TYPES:
        score += 18
        evidence.append('强格式/提供商专用凭据特征')
    if credential_type in PAIR_TYPES:
        score += 12
        evidence.append('同一对象中发现成对身份凭据')
    if has_context:
        score += 8
        evidence.append('邻近上下文含 secret/token/password 等敏感语义')
    if entropy >= 4.0:
        score += 7
        evidence.append(f'高随机熵 {entropy:.2f}')
    elif entropy >= 3.2:
        score += 4
        evidence.append(f'中等随机熵 {entropy:.2f}')

    loc = locator or ''
    if SENSITIVE_PATH.search(loc):
        score += 8
        evidence.append('位于配置/密钥/CI 等敏感路径')
    if TEST_PATH.search(loc):
        score -= 15
        evidence.append('路径呈现测试/样例特征，风险降权')
    if placeholder:
        score -= 60
        evidence.append('值包含测试/占位标记，强降权')
    if exposure_state == 'history':
        score += 3
        evidence.append('历史提交中仍可追溯到凭据')

    for x in extra_evidence or []:
        if x and x not in evidence:
            evidence.append(x)

    score = max(0, min(100, score))
    return RiskResult(score=score, severity=severity_from_score(score), evidence=evidence)
