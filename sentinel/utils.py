import hashlib, math, re

def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {}
    for c in s:
        counts[c] = counts.get(c, 0) + 1
    n = len(s)
    return -sum((v/n) * math.log2(v/n) for v in counts.values())

def fingerprint(secret: str) -> str:
    return hashlib.sha256(secret.encode('utf-8', errors='ignore')).hexdigest()

def mask(secret: str) -> str:
    if len(secret) <= 8:
        return '*' * len(secret)
    return secret[:4] + '*' * (len(secret)-8) + secret[-4:]

CONTEXT_WORDS = re.compile(r'(?i)(secret|token|password|passwd|pwd|api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret|database|jdbc|redis|mysql|postgres|账号|密码|密钥|凭据)')

def context_score(text: str, start: int, end: int, radius: int = 80) -> float:
    ctx = text[max(0, start-radius): min(len(text), end+radius)]
    return 0.15 if CONTEXT_WORDS.search(ctx) else 0.0
