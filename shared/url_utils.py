"""URL parsing helpers."""

from __future__ import annotations

import re
from urllib.parse import urlparse

# RFC 1035 hostname matcher used by the custom-domains code path.
# Labels: 1-63 chars, [a-z0-9-], no leading/trailing hyphen.
# Total length: ≤ 253.
# TLD: either ≥2 alpha chars OR an ASCII-encoded punycode label (``xn--…``)
# so internationalised TLDs (.中国 → ``xn--fiqs8s``) are accepted.
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)"
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$"
)
_FORBIDDEN_CHARS = re.compile(r"[\x00-\x1F\x7F-\x9F<>\"'`\\]")


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


def normalise_fqdn(value: object) -> str:
    """Strict canonical form for custom-domain fqdns.

    Strips whitespace, lowercases, drops a trailing dot, and validates
    against RFC 1035 hostname syntax (with punycode TLD support). Raises
    ``ValueError`` for empty / bad-character / malformed input.

    Single source of truth — used by the document model, request DTO,
    AND the repository so a normalised lookup never misses because the
    persisted form drifted from the input form.
    """
    if value is None:
        raise ValueError("fqdn is required")
    normalised = str(value).strip().lower().rstrip(".")
    if not normalised:
        raise ValueError("fqdn is required")
    if _FORBIDDEN_CHARS.search(normalised):
        raise ValueError(f"fqdn contains forbidden characters: {value!r}")
    if not _HOSTNAME_RE.match(normalised):
        raise ValueError(f"fqdn does not look like a valid hostname: {value!r}")
    return normalised
