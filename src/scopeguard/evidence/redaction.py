from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any


PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(r"(?i)(authorization\s*:\s*bearer\s+)[A-Za-z0-9._~-]+"),
        r"\1[REDACTED]",
    ),
    (
        re.compile(r"(?i)(set-cookie\s*:\s*)(.+)"),
        r"\1[REDACTED]",
    ),
    (
        re.compile(r"(?i)(cookie\s*:\s*)(.+)"),
        r"\1[REDACTED]",
    ),
    (
        re.compile(
            r"(?i)([?&](?:token|access_token|id_token|refresh_token|session|sid|api[_-]?key|apikey|secret|password)=)[^&\s]+"
        ),
        r"\1[REDACTED]",
    ),
    (
        re.compile(r"(?i)\b(?:token|access_token|id_token|refresh_token|session|sid|api[_-]?key|apikey|secret|password)=[^&\s]+"),
        "[REDACTED]",
    ),
    (
        re.compile(r"eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+"),
        "[REDACTED-JWT]",
    ),
]

SENSITIVE_KEYS = {
    "authorization",
    "cookie",
    "set-cookie",
    "token",
    "access_token",
    "id_token",
    "refresh_token",
    "session",
    "sid",
    "api-key",
    "api_key",
    "apikey",
    "secret",
    "password",
}


def redact_sensitive_text(text: str) -> str:
    redacted = text
    for pattern, replacement in PATTERNS:
        redacted = pattern.sub(replacement, redacted)
    return redacted


def redact_sensitive_value(value: Any) -> Any:
    if isinstance(value, str):
        return redact_sensitive_text(value)
    if isinstance(value, Mapping):
        redacted: dict[Any, Any] = {}
        for key, item in value.items():
            if str(key).lower() in SENSITIVE_KEYS:
                redacted[key] = "[REDACTED]"
            else:
                redacted[key] = redact_sensitive_value(item)
        return redacted
    if isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray, str)):
        return [redact_sensitive_value(item) for item in value]
    return value
