"""
POST /api/v1/shorten — create a shortened URL.

Returns 201 on success with the URL details.
Auth is optional; API key users require `shorten:create` or `admin:all` scope.

When ``domain`` is supplied the route layer asserts the caller owns an ACTIVE
custom domain with that fqdn before delegating to ``UrlService.create``. Short
URL is built from the custom host. Anonymous callers cannot specify ``domain``.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request

from dependencies import (
    SHORTEN_SCOPES,
    CurrentUser,
    CustomDomainSvc,
    FeatureFlagSvc,
    Settings,
    UrlSvc,
    optional_scopes_verified,
)
from errors import AuthenticationError, ForbiddenError
from middleware.openapi import AUTH_RESPONSES, OPTIONAL_AUTH_SECURITY
from middleware.rate_limiter import Limits, dynamic_limit, limiter
from schemas.dto.requests.url import AliasCheckQuery, CreateUrlRequest
from schemas.dto.responses.url import AliasCheckResponse, UrlResponse
from shared.ip_utils import get_client_ip

router = APIRouter(tags=["URL Shortening"])

_shorten_limit, _shorten_key = dynamic_limit(Limits.API_AUTHED, Limits.API_ANON)
_check_limit, _check_key = dynamic_limit(Limits.API_CHECK_AUTHED, Limits.API_CHECK_ANON)

GEO_TARGETING_FLAG = "geo_targeting"


async def require_geo_targeting_enabled(
    flag_svc: FeatureFlagSvc, user: CurrentUser
) -> None:
    """Flag gate for writing geo_rules. 403 (not 404) — geo_rules is a field
    inside shared endpoints, so hiding the endpoint isn't an option."""
    if not await flag_svc.is_enabled(GEO_TARGETING_FLAG, user):
        raise ForbiddenError("Geo targeting is not enabled for this account")


@router.post(
    "/shorten",
    status_code=201,
    responses=AUTH_RESPONSES,
    openapi_extra=OPTIONAL_AUTH_SECURITY,
    operation_id="shortenUrl",
    summary="Create Shortened URL",
)
@limiter.limit(_shorten_limit, key_func=_shorten_key)
async def shorten_v1(
    request: Request,
    body: CreateUrlRequest,
    url_service: UrlSvc,
    custom_domain_service: CustomDomainSvc,
    settings: Settings,
    flag_svc: FeatureFlagSvc,
    user: CurrentUser | None = Depends(optional_scopes_verified(SHORTEN_SCOPES)),  # noqa: B008
) -> UrlResponse:
    """Create a new shortened URL.

    Create a shortened URL with optional customization including password
    protection, expiration, click limits, and bot blocking. Authenticated
    users may target an owned, ACTIVE custom domain via the ``domain`` field.

    **Authentication**: Optional — higher rate limits when authenticated.
    Required if ``domain`` is supplied.

    **API Key Scope**: `shorten:create` or `admin:all`

    **Rate Limits**:

    - Authenticated: 60/min, 5,000/day
    - Anonymous: 20/min, 1,000/day

    **Anonymous Usage Consequences**:

    - Lower rate limits
    - Cannot manage or view URLs later
    - Cannot use private stats
    - URLs not linked to any account
    - Cannot use custom domains
    - Cannot use geo targeting
    """
    owner_id = user.user_id if user is not None else None
    client_ip = get_client_ip(request)

    if body.geo_rules:
        if user is None:
            raise AuthenticationError("Authentication required to set geo_rules")
        await require_geo_targeting_enabled(flag_svc, user)

    if body.domain and body.domain != settings.system_default_domain:
        if user is None:
            raise AuthenticationError(
                "Authentication required to shorten on a custom domain"
            )
        await custom_domain_service.assert_owned_and_active(user, body.domain)
        base_url = f"https://{body.domain}"
        scoped_domain: str | None = body.domain
    else:
        base_url = settings.app_url
        scoped_domain = None

    doc = await url_service.create(body, owner_id, client_ip, domain=scoped_domain)
    return UrlResponse.from_doc(doc, base_url)


@router.get(
    "/shorten/check-alias",
    responses=AUTH_RESPONSES,
    openapi_extra=OPTIONAL_AUTH_SECURITY,
    operation_id="checkAliasAvailability",
    summary="Check Alias Availability",
)
@limiter.limit(_check_limit, key_func=_check_key)
async def check_alias(
    request: Request,
    url_service: UrlSvc,
    custom_domain_service: CustomDomainSvc,
    settings: Settings,
    query: Annotated[AliasCheckQuery, Query()],
    user: CurrentUser | None = Depends(optional_scopes_verified(SHORTEN_SCOPES)),  # noqa: B008
) -> AliasCheckResponse:
    """Check whether a proposed alias would be accepted by POST /api/v1/shorten.

    Reason codes on a negative result (``length``/``format``/``taken``) let the
    UI render precise inline feedback without duplicating the validation rules.

    Pass ``domain`` to scope the check to a custom-domain tenant — required
    for the create modal's live availability indicator when the user has
    picked a non-default domain. Authz mirrors the shorten endpoint: anon
    callers can't probe custom domains; authed callers must own the target.

    **Authentication**: Optional — higher rate limits when authenticated.
    Required if ``domain`` is supplied.
    """
    if query.domain and query.domain != settings.system_default_domain:
        if user is None:
            raise AuthenticationError(
                "Authentication required to check aliases on a custom domain"
            )
        await custom_domain_service.assert_owned_and_active(user, query.domain)
        scope: str | None = query.domain
    else:
        scope = None
    result = await url_service.check_alias(query.alias, domain=scope)
    return AliasCheckResponse(
        available=result == "available",
        reason=None if result == "available" else result,
    )
