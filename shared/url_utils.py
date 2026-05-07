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
