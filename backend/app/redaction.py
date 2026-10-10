import re

PATTERNS = [
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|AIza[A-Za-z0-9_-]{30,}|AKIA[A-Z0-9]{16}|sk-[A-Za-z0-9_-]{20,})"),
    re.compile(r"(?i)(?:password|passwd|secret|token|api[_-]?key|credential|authorization)['\"]?\s*[=:]\s*['\"]?([^\s'\";,}]{4,})"),
    re.compile(r"(?i)(?:bearer|basic)\s+([A-Za-z0-9_./+=-]{8,})"),
    re.compile(r"https?://[^\s/:]+:([^\s/@]+)@"),
]


def mask(text: str, secrets: list[str] | None = None) -> str:
    for secret in sorted(secrets or [], key=len, reverse=True):
        if len(secret) >= 4:
            text = text.replace(secret, "[REDACTED]")
    for pattern in PATTERNS:
        def replace(match):
            if match.lastindex:
                value = match.group(match.lastindex)
                return match.group(0).replace(value, "[REDACTED]")
            return "\n".join("[REDACTED]" for _ in match.group(0).split("\n"))
        text = pattern.sub(replace, text)
    return text


def scrub(value, secrets=None):
    if isinstance(value, str):
        return mask(value, secrets)
    if isinstance(value, list):
        return [scrub(item, secrets) for item in value]
    if isinstance(value, dict):
        return {key: scrub(item, secrets) for key, item in value.items()}
    return value
