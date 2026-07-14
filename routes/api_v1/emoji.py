"""GET /api/v1/emoji-set — the accepted emoji-alias catalogue.

A public, unauthenticated read of the emoji-alias acceptance policy: the
set a user may choose from (the picker's list), the auto-generation pool,
the version caps, and the grapheme limit. It is a static, build-time
derived constant, so clients (an emoji picker, a dice suggester) have one
source of truth instead of replicating the policy. Both sets flow from
``shared.emoji_policy`` so they can never drift from the validator that
accepts aliases.

Caching is a day of freshness with a week of stale-while-revalidate, plus
a content-derived ETag so a deploy that bumps the emoji set (new Unicode
version) yields a new ETag and revalidates to fresh data instead of
stranding clients on a stale list. Low-volume, interaction-gated read: the
browser HTTP cache and a client memo carry it, no edge or server cache.
"""

from __future__ import annotations

import hashlib

from fastapi import APIRouter, Request, Response

from dependencies import Settings
from middleware.openapi import ERROR_RESPONSES, PUBLIC_SECURITY
from middleware.rate_limiter import Limits, limiter
from schemas.dto.responses.emoji import EmojiEntry, EmojiSetResponse
from shared.emoji_policy import (
    accepted_singletons,
    emoji_display_name,
    emoji_keywords,
    generation_pool,
)

router = APIRouter(tags=["URL Shortening"])

# A day fresh, a week of serve-stale-while-revalidating in the background.
# Not `immutable`: the set changes on deploy, and the ETag below makes that
# revalidation return fresh data rather than stranding clients until TTL.
_CACHE_CONTROL = "public, max-age=86400, stale-while-revalidate=604800"


def _build_set(settings) -> EmojiSetResponse:
    gen = set(generation_pool(settings.emoji_generate_max_version))
    emoji_list = []
    for char in accepted_singletons(settings.emoji_accept_max_version):
        keywords = emoji_keywords(char)
        emoji_list.append(
            EmojiEntry(
                c=char,
                n=emoji_display_name(char),
                gen=char in gen,
                k=list(keywords) or None,
            )
        )
    return EmojiSetResponse(
        accept_max_version=settings.emoji_accept_max_version,
        generate_max_version=settings.emoji_generate_max_version,
        max_graphemes=settings.max_emoji_alias_length,
        emoji=emoji_list,
    )


def _etag(payload: EmojiSetResponse) -> str:
    """A strong, quoted ETag derived from the set's content and caps.

    Any change to the caps, the emoji list, or an entry's name/gen/aliases
    (a deploy bumping the pinned ``emoji`` package, or a settings override)
    changes the digest, so the ETag revalidates to fresh data for free.
    """
    h = hashlib.sha256()
    h.update(
        f"{payload.accept_max_version}|{payload.generate_max_version}"
        f"|{payload.max_graphemes}|".encode()
    )
    for entry in payload.emoji:
        h.update(entry.c.encode())
        h.update(b"1" if entry.gen else b"0")
        h.update(entry.n.encode())
        h.update(",".join(entry.k or ()).encode())
        h.update(b"\x00")
    return f'"{h.hexdigest()[:16]}"'


@router.get(
    "/emoji-set",
    responses=ERROR_RESPONSES,
    openapi_extra=PUBLIC_SECURITY,
    operation_id="getEmojiSet",
    summary="Accepted Emoji Set",
    response_model_exclude_none=True,
)
@limiter.limit(Limits.API_CHECK_ANON)
async def emoji_set(
    request: Request,
    response: Response,
    settings: Settings,
) -> EmojiSetResponse:
    """Return the accepted emoji catalogue and its policy caps.

    ``emoji`` lists every single-codepoint emoji a custom alias may use
    (the picker's list). Each entry carries ``c`` (the raw canonical
    character), ``n`` (a searchable name like "rocket"), ``gen`` (whether
    it is in the server's auto-generation pool), and an optional ``k``
    (extra search aliases when the source lists any). Skin tone is a
    client-side modifier appended to a base emoji, so skin-tone variants
    are not enumerated. Categories are not exposed by the source data, so
    a picker relies on search and recents.

    **Authentication**: None. The response is identical for everyone.

    **Caching**: Fresh for a day, then served stale for a week while
    revalidating. A content-derived ``ETag`` is returned; send it back as
    ``If-None-Match`` to get a ``304`` when the set is unchanged.

    **Rate Limits**: 60/min, 2,000/day.
    """
    payload = _build_set(settings)
    etag = _etag(payload)

    if_none_match = request.headers.get("if-none-match", "")
    if etag in {tag.strip() for tag in if_none_match.split(",")}:
        return Response(
            status_code=304,
            headers={"ETag": etag, "Cache-Control": _CACHE_CONTROL},
        )

    response.headers["Cache-Control"] = _CACHE_CONTROL
    response.headers["ETag"] = etag
    return payload
