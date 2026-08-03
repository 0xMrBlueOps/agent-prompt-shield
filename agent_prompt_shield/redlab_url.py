from __future__ import annotations

import urllib.parse


def validate_provider_url(value: str) -> str:
    """Validate a provider endpoint before credentials or request objects are created."""
    if not value or value != value.strip():
        raise ValueError("base_url must be a non-empty absolute HTTPS URL")
    if any(ord(char) < 32 or char.isspace() for char in value):
        raise ValueError("base_url must not contain whitespace or control characters")
    try:
        parsed = urllib.parse.urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise ValueError("base_url is malformed") from exc
    if parsed.scheme.lower() != "https":
        raise ValueError("base_url must use HTTPS")
    if not parsed.netloc or not parsed.hostname:
        raise ValueError("base_url must include a valid hostname")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("base_url must not contain embedded credentials")
    if parsed.fragment:
        raise ValueError("base_url must not contain a fragment")
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("base_url contains an invalid port")
    return value
