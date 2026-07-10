"""
Feature flag service.

Public API is one method: ``is_enabled(name, user) -> bool``. Default-deny
on every error path:

  - Doc missing                     → False (forces explicit registration)
  - Doc.enabled = False             → False
  - rollout_type = OFF              → False (kill switch)
  - user is None on a non-EVERYONE  → False
  - Cache + repo failure            → False (with logged error)

The service consults a read-through Redis cache (60s positive TTL, 30s
negative TTL). Flag mutations happen via direct mongosh edits with no app
event, so changes propagate within the cache TTL window. This is acceptable
for non-emergency rollouts; admin scripts can call ``cache.invalidate(name)``
for an immediate flush after a hot edit.

Stable hashing uses ``blake2b(salt=name + user_id)`` so the same user gets
different positions in different flags' rollouts, enabling independent
percentage and hex-digit gates per feature.
"""

from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING

from bson import ObjectId

from errors import ForbiddenError, NotFoundError
from infrastructure.cache.feature_flag_cache import (
    NEGATIVE_MISS,
    FeatureFlagCache,
)
from infrastructure.logging import get_logger
from repositories.feature_flag_repository import FeatureFlagRepository
from schemas.enums.rollout_type import RolloutType
from schemas.models.feature_flag import FeatureFlagDoc

if TYPE_CHECKING:
    # CurrentUser lives in dependencies.auth which imports back through
    # dependencies/__init__.py — avoid the circular import by importing the
    # type only for type-checking. ``__future__ annotations`` makes the
    # runtime annotation a string so the import is never resolved at runtime.
    from dependencies.auth import CurrentUser

log = get_logger(__name__)

# Known flag names. Flag docs are edited directly in Mongo, so these
# constants are the closest thing to a registry — code references flags
# through them, never through bare string literals at call sites.
GEO_TARGETING_FLAG = "geo_targeting"


def _stable_hash(user_id: ObjectId, salt: str) -> int:
    """Return 0-99 deterministically per ``(user_id, salt)``.

    Used by ``RolloutType.PERCENTAGE``. The salt is the flag name so the same
    user has independent positions across different flags' rollouts.
    """
    h = hashlib.blake2b(f"{salt}:{user_id}".encode(), digest_size=4).digest()
    return int.from_bytes(h, "big") % 100


def _digit_bucket(user_id: ObjectId, salt: str) -> str:
    """Return a single hex digit (0-f) deterministically per ``(user_id, salt)``.

    Used by ``RolloutType.HEX_DIGIT``. 16 buckets, each ≈6.25% of users.
    """
    h = hashlib.blake2b(f"{salt}:{user_id}".encode(), digest_size=1).hexdigest()
    return h[0]


class FeatureFlagService:
    def __init__(
        self,
        repo: FeatureFlagRepository,
        cache: FeatureFlagCache,
    ) -> None:
        self._repo = repo
        self._cache = cache

    async def is_enabled(self, name: str, user: CurrentUser | None) -> bool:
        """Return whether ``name`` is enabled for ``user``.

        Default-deny on any error or unregistered flag.
        """
        flag = await self._lookup(name)
        if flag is None or not flag.enabled:
            return False

        rollout = flag.rollout_type

        if rollout == RolloutType.OFF:
            return False
        if rollout == RolloutType.EVERYONE:
            return True

        # All non-EVERYONE rollouts require an authenticated user — anonymous
        # callers get default-deny.
        if user is None:
            return False

        if rollout == RolloutType.ALLOWLIST:
            return flag.is_user_in_allowlist(user.user_id, _email_of(user))

        if rollout == RolloutType.PERCENTAGE:
            return _stable_hash(user.user_id, salt=flag.name) < flag.percentage

        if rollout == RolloutType.HEX_DIGIT:
            return _digit_bucket(user.user_id, salt=flag.name) in flag.enabled_digits

        if rollout == RolloutType.TIER:
            # Default-deny when flag.tier is unset — None == None would
            # otherwise enable for every user with no tier attribute.
            if flag.tier is None:
                return False
            return getattr(user, "tier", None) == flag.tier

        # Unreachable today — Pydantic validates rollout_type against the
        # RolloutType enum. Kept as default-deny if the field is ever widened.
        log.warning("feature_flag_unknown_rollout", name=name, rollout=str(rollout))
        return False

    async def require(
        self, name: str, user: CurrentUser | None, *, hide: bool = False
    ) -> None:
        """Raise unless ``name`` is enabled for ``user``.

        403 by default — the right signal for flag-gated FIELDS on shared
        endpoints, which appear in public OpenAPI docs and can't be
        concealed. Pass ``hide=True`` for whole-endpoint features whose
        existence is itself gated (the custom-domains pattern): 404, so
        non-allowlisted callers can't tell the feature exists.
        """
        if await self.is_enabled(name, user):
            return
        if hide:
            raise NotFoundError("not found")
        feature = name.replace("_", " ").capitalize()
        raise ForbiddenError(f"{feature} is not enabled for this account")

    async def _lookup(self, name: str) -> FeatureFlagDoc | None:
        """Fetch a flag through cache → repo, returning None for unregistered."""
        try:
            cached = await self._cache.get(name)
        except Exception as e:
            log.warning("feature_flag_cache_lookup_error", name=name, error=str(e))
            cached = None

        if cached is NEGATIVE_MISS:
            return None
        if isinstance(cached, FeatureFlagDoc):
            return cached

        try:
            doc = await self._repo.find_by_name(name)
        except Exception as e:
            log.error("feature_flag_repo_lookup_error", name=name, error=str(e))
            return None

        if doc is None:
            await self._cache.set_negative(name)
            return None
        await self._cache.set(name, doc)
        return doc


def _email_of(user: CurrentUser) -> str | None:
    """Best-effort email extraction.

    ``CurrentUser`` has ``user_id`` always but email is not on the dataclass
    today. When auth resolves a JWT or API key the user's email lives on the
    underlying ``UserDoc`` and isn't propagated here. For now allowlist by
    email is best-effort: if the email field is added later, this picks it
    up via ``getattr`` without code changes.
    """
    return getattr(user, "email", None)
