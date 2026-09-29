from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Optional


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def parse_time(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    v = value.strip()
    try:
        d = datetime.fromisoformat(v.replace('Z', '+00:00'))
        if d.tzinfo is None:
            d = d.replace(tzinfo=timezone.utc)
        return d.astimezone(timezone.utc)
    except Exception:
        pass
    try:
        d = parsedate_to_datetime(v)
        if d.tzinfo is None:
            d = d.replace(tzinfo=timezone.utc)
        return d.astimezone(timezone.utc)
    except Exception:
        return None


def latency_ms(published_at: Optional[str], observed_at: Optional[str]) -> Optional[float]:
    p = parse_time(published_at)
    o = parse_time(observed_at)
    if not p or not o:
        return None
    ms = (o - p).total_seconds() * 1000
    if ms < 0:
        return None
    return round(ms, 1)
