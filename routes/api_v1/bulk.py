"""
POST /api/v1/urls/bulk/delete — delete up to 100 URLs by id
POST /api/v1/urls/bulk/status — activate/deactivate up to 100 URLs
POST /api/v1/urls/bulk/expiry — set/clear expiry on up to 100 URLs

The backend counterpart to the dashboard's multi-select action bar: one
request per user intent instead of a client-side fan-out over the
per-item routes (whose budgets are priced for per-item use).

All endpoints require authentication. API key users require
``urls:manage`` or ``admin:all`` scope — bulk grants no capability a
loop over single-item calls doesn't already have, so there is no bulk
scope.

Shared contract: the batch always answers 200 with a summary and one
result row per unique id (even all-failed — per-item failures are
answers, not errors). 4xx is reserved for envelope rejection where zero
items were attempted: malformed/empty/over-cap ids, invalid op param,
missing scope, rate limit. Retrying an identical batch is safe by
construction: every op sets an absolute value or deletes.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from dependencies import (
    URL_MANAGEMENT_SCOPES,
    BulkUrlSvc,
    CurrentUser,
    require_scopes,
)
from middleware.openapi import ERROR_RESPONSES
from middleware.rate_limiter import Limits, limiter
from schemas.dto.requests.bulk import (
    BulkDeleteUrlsRequest,
    BulkUpdateExpiryRequest,
    BulkUpdateStatusRequest,
)
from schemas.dto.responses.bulk import BulkUrlOperationResponse

router = APIRouter(tags=["Link Management"])


@router.post(
    "/urls/bulk/delete",
    responses=ERROR_RESPONSES,
    operation_id="bulkDeleteUrlsByIds",
    summary="Bulk Delete URLs",
)
@limiter.limit(Limits.URL_BULK_MUTATE_DELETE)
async def bulk_delete_urls_v1(
    request: Request,
    body: BulkDeleteUrlsRequest,
    bulk_service: BulkUrlSvc,
    user: CurrentUser = Depends(require_scopes(URL_MANAGEMENT_SCOPES)),  # noqa: B008
) -> BulkUrlOperationResponse:
    """Permanently delete up to 100 URLs you own, addressed by id.

    **This action is irreversible.** Deleted aliases become available
    for anyone to claim. Historical analytics are not removed.

    Not to be confused with `DELETE /api/v1/urls?domain=` (bulk delete
    by custom domain): that operation answers "everything on this
    domain", this one answers "exactly these links".

    **Per-item verdicts** (`error_code`): `not_found` — no such URL in
    your account (an id you don't own answers the same); `forbidden` —
    the URL is admin-blocked and cannot be deleted.

    **Retry semantics**: re-sending the batch after a timeout is safe;
    already-deleted ids report `not_found`, which a client should treat
    as success-equivalent for delete.

    **Rate Limits**: 5/min, 50/day — counted per request, not per id.
    """
    return await bulk_service.bulk_delete(body.object_ids(), user.user_id)


@router.post(
    "/urls/bulk/status",
    responses=ERROR_RESPONSES,
    operation_id="bulkUpdateUrlStatus",
    summary="Bulk Update URL Status",
)
@limiter.limit(Limits.URL_BULK_STATUS)
async def bulk_update_url_status_v1(
    request: Request,
    body: BulkUpdateStatusRequest,
    bulk_service: BulkUrlSvc,
    user: CurrentUser = Depends(require_scopes(URL_MANAGEMENT_SCOPES)),  # noqa: B008
) -> BulkUrlOperationResponse:
    """Activate or deactivate up to 100 URLs you own in one request.

    Semantics match the single-item status endpoint exactly: `ACTIVE`
    enables redirects, `INACTIVE` disables them, `EXPIRED` URLs set to
    `ACTIVE` reactivate, and setting the status a link already has is a
    success no-op.

    **Per-item verdicts** (`error_code`): `not_found` — no such URL in
    your account; `forbidden` — the URL is admin-blocked and cannot be
    modified.

    **Rate Limits**: 10/min, 100/day — counted per request, not per id.
    """
    return await bulk_service.bulk_set_status(
        body.object_ids(), body.status, user.user_id
    )


@router.post(
    "/urls/bulk/expiry",
    responses=ERROR_RESPONSES,
    operation_id="bulkUpdateUrlExpiry",
    summary="Bulk Update URL Expiry",
)
@limiter.limit(Limits.URL_BULK_EXPIRY)
async def bulk_update_url_expiry_v1(
    request: Request,
    body: BulkUpdateExpiryRequest,
    bulk_service: BulkUrlSvc,
    user: CurrentUser = Depends(require_scopes(URL_MANAGEMENT_SCOPES)),  # noqa: B008
) -> BulkUrlOperationResponse:
    """Set or clear the expiration on up to 100 URLs you own.

    One value for the whole batch — ISO 8601 or epoch seconds, must be
    in the future (a past value rejects the whole request; it could
    never be right for any item). `null` clears expiry. `EXPIRED` URLs
    whose expiry is extended or cleared reactivate, exactly like the
    single-item update.

    **Per-item verdicts** (`error_code`): `not_found` — no such URL in
    your account; `forbidden` — the URL is admin-blocked and cannot be
    modified.

    **Rate Limits**: 10/min, 100/day — counted per request, not per id.
    """
    return await bulk_service.bulk_set_expiry(
        body.object_ids(), body.expire_after, user.user_id
    )
