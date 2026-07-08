"""Shared feature-flag gates for /api/v1 endpoints.

Gates for flag-gated FIELDS on shared endpoints live here so multiple route
modules can share them without importing each other's handler modules.

These return 403 when the flag is off — unlike whole-endpoint features such
as custom domains, which 404 to hide their existence. A field on a shared
endpoint can't hide the endpoint, so an honest 403 is the right signal.
"""

from __future__ import annotations

from dependencies import CurrentUser, FeatureFlagSvc
from errors import ForbiddenError

GEO_TARGETING_FLAG = "geo_targeting"


async def require_geo_targeting_enabled(
    flag_svc: FeatureFlagSvc, user: CurrentUser
) -> None:
    if not await flag_svc.is_enabled(GEO_TARGETING_FLAG, user):
        raise ForbiddenError("Geo targeting is not enabled for this account")
