"""
GET    /api/v1/urls            — list authenticated user's shortened URLs
DELETE /api/v1/urls?domain=    — bulk-delete URLs scoped to one custom domain

Requires authentication. Listing returns paginated list with camelCase keys.
Bulk delete is owner-scoped and refuses the system-default namespace.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request

from dependencies import (
    URL_MANAGEMENT_SCOPES,
    URL_READ_SCOPES,
    CurrentUser,
    CustomDomainSvc,
    UrlSvc,
    require_scopes,
)
from errors import ValidationError
from middleware.openapi import AUTH_RESPONSES, ERROR_RESPONSES
from middleware.rate_limiter import Limits, limiter
from schemas.dto.requests.url import ListUrlsQuery
from schemas.dto.responses.url import (
    BulkDeleteUrlsResponse,
    UrlListItem,
    UrlListResponse,
)
from shared.url_utils import normalise_fqdn

router = APIRouter(tags=["Link Management"])


@router.get(
    "/urls",
    responses=ERROR_RESPONSES,
    operation_id="listUrls",
    summary="List Your URLs",
)
@limiter.limit(Limits.API_AUTHED)
async def list_urls_v1(
    request: Request,
    query: Annotated[ListUrlsQuery, Query()],
    url_service: UrlSvc,
    user: CurrentUser = Depends(require_scopes(URL_READ_SCOPES)),  # noqa: B008
) -> UrlListResponse:
    """List all URLs owned by the authenticated user.

    Returns a paginated list of shortened URLs with support for filtering,
    sorting, and full-text search on aliases and destination URLs.

    **Authentication**: Required.

    **API Key Scope**: `urls:manage`, `urls:read`, or `admin:all`

    **Rate Limits**: 60/min, 5,000/day

    **Pagination**: Use `page` and `pageSize` query params. Response includes
    `hasNext` boolean and `total` count.

    **Sorting**: Sort by `created_at`, `last_click`, or `total_clicks` in
    ascending or descending order.

    **Filtering**: Pass a JSON-encoded `filter` parameter with fields like
    `status`, `createdAfter`, `createdBefore`, `passwordSet`, `maxClicksSet`,
    and `search`.
    """
    result = await url_service.list_by_owner(user.user_id, query)
    result["items"] = [UrlListItem.from_doc(doc) for doc in result["items"]]
    return result


@router.delete(
    "/urls",
    responses=AUTH_RESPONSES,
    operation_id="bulkDeleteUrls",
    summary="Bulk Delete URLs on a Custom Domain",
)
@limiter.limit(Limits.URL_BULK_DELETE)
async def bulk_delete_urls_v1(
    request: Request,
    domain: Annotated[
        str,
        Query(
            min_length=1,
            max_length=253,
            description="Custom domain fqdn whose URLs should be deleted.",
            examples=["links.acme.com"],
        ),
    ],
    url_service: UrlSvc,
    custom_domain_service: CustomDomainSvc,
    user: CurrentUser = Depends(require_scopes(URL_MANAGEMENT_SCOPES)),  # noqa: B008
) -> BulkDeleteUrlsResponse:
    """Bulk-delete all URLs the caller owns on the given custom domain.

    **Authentication**: Required.

    **API Key Scope**: `urls:manage` or `admin:all`

    **Rate Limits**: 5/min, 50/day.

    **Restrictions**: refuses the system-default domain — protects against
    accidental nuke of the user's entire spoo.me URL inventory. Caller must
    own the domain.
    """
    try:
        fqdn = normalise_fqdn(domain)
    except ValueError as exc:
        raise ValidationError(str(exc), field="domain") from exc
    await custom_domain_service.assert_owned(user, fqdn)
    count = await url_service.delete_all_by_domain(user.user_id, fqdn)
    return BulkDeleteUrlsResponse(
        message=f"deleted {count} URL(s) on {fqdn}",
        count=count,
        domain=fqdn,
    )
