"""Write-gate for the custom meta-tags field, shared by shorten + management.

403 rather than custom-domains' 404 pattern: the field lives inside shared
endpoints, so hiding the feature's existence buys nothing — return an
actionable error instead. Clearing (``meta_tags: null``) is never gated:
users must always be able to remove their own tags, including after a
downgrade.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from errors import ForbiddenError

if TYPE_CHECKING:
    from dependencies import CurrentUser
    from services.feature_flag_service import FeatureFlagService

META_TAGS_FLAG = "custom_meta_tags"


async def require_meta_tags_enabled(
    flag_svc: FeatureFlagService, user: CurrentUser | None
) -> None:
    """Raise 403 unless the caller may WRITE meta_tags."""
    if user is None or not user.email_verified:
        raise ForbiddenError("meta_tags requires a verified account")
    if not await flag_svc.is_enabled(META_TAGS_FLAG, user):
        raise ForbiddenError("meta_tags is not available on your account")
