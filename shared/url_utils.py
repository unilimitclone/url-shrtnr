"""URL parsing helpers."""

from __future__ import annotations

from urllib.parse import urlparse


def extract_hostname(url: str | None) -> str | None:
    """Return hostname from URL, or None if unparseable."""
    if not url:
        return None
    try:
        return urlparse(url).hostname
    except Exception:
        return None


def extract_fqdn(url: str) -> str:
    """Return the canonical fqdn from a URL.

    Lowercased, trailing dot stripped, port discarded. Used as the canonical
    domain key across config, cache, and middleware so the same hostname
    always maps to the same string.

    Falls back to ``"localhost"`` for inputs without a parseable host
    (raw paths, garbage strings) — defensive shape for callers that feed
    arbitrary user input.
    """
    host = extract_hostname(url)
    if not host:
        return "localhost"
    return host.lower().rstrip(".")
