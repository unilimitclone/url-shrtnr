"""
GET    /api/v1/me/features       — per-account feature availability
GET    /api/v1/me/layouts/{page} — fetch the saved dashboard layout (null = default)
PUT    /api/v1/me/layouts/{page} — save the layout document verbatim
DELETE /api/v1/me/layouts/{page} — reset to default (idempotent)

Per-user preferences namespace. Layout documents are client-owned JSON blobs:
the frontend versions and validates them, the server stores them opaquely
keyed by (user, page). Features mirror the flag service's answers as data —
the read side of gates the write endpoints already enforce.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Path, Request

from dependencies import AuthUser, FeatureFlagSvc, PageLayoutSvc
from middleware.openapi import AUTH_RESPONSES
from middleware.rate_limiter import Limits, limiter
from schemas.dto.requests.layouts import PutLayoutRequest
from schemas.dto.responses.features import FeaturesResponse
from schemas.dto.responses.layouts import LayoutResponse

router = APIRouter(prefix="/me", tags=["Me"])


@router.get(
    "/features",
    responses=AUTH_RESPONSES,
    operation_id="getMyFeatures",
    summary="Get Feature Availability",
)
@limiter.limit(Limits.DASHBOARD_READ)
async def get_my_features(
    request: Request,
    user: AuthUser,
    flag_service: FeatureFlagSvc,
) -> FeaturesResponse:
    """Return the availability state of every gated feature for this account.

    States: `enabled` (render it), `hidden` (the feature doesn't exist for
    this account), `locked` (reserved — render as upgrade-gated once plans
    ship). Treat features missing from the map as `hidden`. Never used for
    enforcement — the write endpoints enforce the same gates server-side.

    **Authentication**: Required.
    """
    return FeaturesResponse(features=await flag_service.states_for(user))

PagePath = Annotated[
    str,
    Path(
        min_length=1,
        max_length=32,
        pattern=r"^[a-z0-9_-]+$",
        description="Layout slot, e.g. `analytics`",
    ),
]


@router.get(
    "/layouts/{page}",
    responses=AUTH_RESPONSES,
    operation_id="getPageLayout",
    summary="Get Page Layout",
)
@limiter.limit(Limits.LAYOUT_READ)
async def get_page_layout(
    request: Request,
    page: PagePath,
    user: AuthUser,
    layout_service: PageLayoutSvc,
) -> LayoutResponse:
    """Fetch the saved dashboard layout for a page.

    Returns `layout: null` when the user has never customized this page —
    clients render their built-in default in that case.

    **Authentication**: Required.
    """
    return LayoutResponse(layout=await layout_service.get_layout(user.user_id, page))


@router.put(
    "/layouts/{page}",
    responses=AUTH_RESPONSES,
    operation_id="putPageLayout",
    summary="Save Page Layout",
)
@limiter.limit(Limits.LAYOUT_WRITE)
async def put_page_layout(
    request: Request,
    page: PagePath,
    body: PutLayoutRequest,
    user: AuthUser,
    layout_service: PageLayoutSvc,
) -> LayoutResponse:
    """Save the layout document for a page.

    The document is stored verbatim (last write wins) and echoed back.
    Versioning and validation are the client's responsibility; the body is
    capped at 32 KiB.

    **Authentication**: Required.
    """
    return LayoutResponse(
        layout=await layout_service.put_layout(user.user_id, page, body.layout)
    )


@router.delete(
    "/layouts/{page}",
    status_code=204,
    responses=AUTH_RESPONSES,
    operation_id="deletePageLayout",
    summary="Reset Page Layout",
)
@limiter.limit(Limits.LAYOUT_DELETE)
async def delete_page_layout(
    request: Request,
    page: PagePath,
    user: AuthUser,
    layout_service: PageLayoutSvc,
) -> None:
    """Remove the saved layout so the page falls back to the client default.

    Idempotent: returns 204 whether or not an override existed.

    **Authentication**: Required.
    """
    await layout_service.delete_layout(user.user_id, page)
