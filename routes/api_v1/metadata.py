"""GET /api/v1/metadata — fetch & parse a destination's existing meta tags.

The prefill companion to custom meta-tags (Dub precedent: api.dub.co/
metatags): clients call this to pre-populate title/description/image from
the destination before customizing. Auth-required — an anonymous version
would be a free fetch-proxy for the whole internet — with its own tight
rate limit, SSRF-guarded fetching, and Redis caching (1h / 5m negative).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request

from dependencies import URL_READ_SCOPES, CurrentUser, require_scopes
from errors import AppError, ValidationError
from infrastructure.safe_fetch import (
    FetchHardError,
    FetchTransientError,
    fetch_public,
)
from middleware.openapi import AUTH_RESPONSES
from middleware.rate_limiter import Limits, limiter
from schemas.dto.responses.metadata import MetadataResponse
from services.meta_tags.parse_html import parse_meta_tags

router = APIRouter(tags=["Metadata"])

_FETCH_MAX_BYTES = 524_288  # tags must be in the head; 512KB is generous
_FETCH_TIMEOUT = 5.0


class UpstreamUnfetchableError(AppError):
    """The destination can't be fetched or isn't an HTML page."""

    status_code = 422
    error_code = "unfetchable"


class UpstreamTimeoutError(AppError):
    status_code = 504
    error_code = "upstream_timeout"


@router.get(
    "/metadata",
    responses=AUTH_RESPONSES,
    operation_id="getUrlMetadata",
    summary="Fetch Destination Meta Tags",
)
@limiter.limit(Limits.METADATA_FETCH)
async def get_metadata(
    request: Request,
    url: Annotated[
        str,
        Query(
            max_length=2048,
            description="Destination https URL to fetch and parse.",
            examples=["https://example.com/article"],
        ),
    ],
    user: CurrentUser = Depends(require_scopes(URL_READ_SCOPES)),  # noqa: B008
) -> MetadataResponse:
    """Fetch a destination page and return its existing meta tags.

    Use this to prefill ``meta_tags`` before customizing a link's social
    preview. Returns normalized best-pick fields (og → twitter → html
    fallbacks) plus the raw ``og``/``twitter`` tag families.

    **Authentication**: Required. **API Key Scope**: `urls:read`,
    `urls:manage`, or `admin:all`.

    **Rate Limits**: 20/min, 500/day — results are cached ~1h server-side,
    so repeat calls for the same URL are cheap and don't refetch.
    """
    if not url.startswith("https://"):
        raise ValidationError("url must be https", field="url")

    cache = request.app.state.meta_fetch_cache
    cached = await cache.get(url)
    if cached is not None:
        if cached.get("error"):
            raise UpstreamUnfetchableError(cached["error"])
        return MetadataResponse(**cached)

    try:
        fetched = await fetch_public(
            url,
            accept_content=("text/html", "application/xhtml"),
            timeout=_FETCH_TIMEOUT,
            max_bytes=_FETCH_MAX_BYTES,
        )
    except FetchTransientError as exc:
        raise UpstreamTimeoutError("destination did not respond in time") from exc
    except FetchHardError as exc:
        payload = {"error": f"destination is not a fetchable HTML page ({exc})"}
        await cache.set(url, payload, negative=True)
        raise UpstreamUnfetchableError(payload["error"]) from exc

    parsed = parse_meta_tags(
        fetched.data.decode("utf-8", errors="replace"), fetched.final_url
    )
    payload = {
        "url": url,
        "final_url": fetched.final_url,
        "title": parsed.title,
        "description": parsed.description,
        "image": parsed.image,
        "color": parsed.color,
        "site_name": parsed.site_name,
        "og": parsed.og,
        "twitter": parsed.twitter,
        "fetched_at": datetime.now(timezone.utc).isoformat(),
    }
    await cache.set(url, payload)
    return MetadataResponse(**payload)
