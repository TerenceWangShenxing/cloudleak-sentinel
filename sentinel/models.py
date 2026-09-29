from dataclasses import dataclass, asdict
from typing import Optional


@dataclass
class Artifact:
    source: str
    locator: str
    content: str
    observed_at: str
    published_at: Optional[str] = None
    channel: Optional[str] = None
    metadata: Optional[dict] = None


@dataclass
class Finding:
    source: str
    locator: str
    credential_type: str
    masked_value: str
    fingerprint: str
    confidence: float
    severity: str
    reason: str
    observed_at: str
    published_at: Optional[str] = None
    channel: Optional[str] = None
    detection_latency_ms: Optional[float] = None
    risk_score: int = 0
    evidence: Optional[list[str]] = None
    exposure_state: str = 'current'

    def to_dict(self):
        return asdict(self)
