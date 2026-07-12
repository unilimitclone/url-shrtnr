"""Alias-resolution dispatch order — single source of truth.

Which URL generation answers a short code is a public contract shared by
every resolving surface (the redirect via ``UrlService._dispatch`` and
the public preview endpoint). The order lives here as one pure function
so the surfaces can never drift: if the length heuristic ever changes,
both learn about it together — otherwise the preview could describe one
link while the redirect serves another under the same code.

Mirrors the original get_url_by_length_and_type() heuristic:
  emoji alias → the emojis collection only
  6 chars     → urls (v1) first, urlsV2 fallback
  anything else → urlsV2 first, urls (v1) fallback
(7-char codes were historically an explicit branch, but their v2-first
order is identical to the default.)
"""

from __future__ import annotations

from schemas.models.url import SchemaVersion
from shared.validators import is_emoji_alias

_V1_FIRST_LENGTH = 6  # v1 codes were generated at exactly this length


def resolution_order(short_code: str) -> tuple[SchemaVersion, ...]:
    """Return the generation lookup order for *short_code*.

    The code must already be percent-decoded (``urllib.parse.unquote``);
    emoji detection tolerates encoded input, but the repositories match
    the decoded form exactly.
    """
    if is_emoji_alias(short_code):
        return (SchemaVersion.EMOJI,)
    if len(short_code) == _V1_FIRST_LENGTH:
        return (SchemaVersion.V1, SchemaVersion.V2)
    return (SchemaVersion.V2, SchemaVersion.V1)
