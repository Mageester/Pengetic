from __future__ import annotations

from scopeguard.evidence.redaction import redact_sensitive_text, redact_sensitive_value


def test_redaction_hides_common_secret_patterns() -> None:
    text = (
        "Authorization: Bearer abc123\n"
        "Cookie: sessionid=secret123\n"
        "https://example.com/?token=abc123&password=hunter2\n"
        "eyJhbGciOiJIUzI1NiJ9.payload.signature"
    )
    redacted = redact_sensitive_text(text)
    assert "abc123" not in redacted
    assert "secret123" not in redacted
    assert "hunter2" not in redacted
    assert "[REDACTED]" in redacted


def test_redaction_recurses_into_structures() -> None:
    payload = {
        "headers": {
            "Authorization": "Bearer abc123",
            "Cookie": "sessionid=secret123",
        },
        "items": ["token=abc123", {"secret": "shh"}],
    }
    redacted = redact_sensitive_value(payload)
    assert "abc123" not in str(redacted)
    assert "secret123" not in str(redacted)

