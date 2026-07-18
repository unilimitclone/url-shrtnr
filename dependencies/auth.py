"""
Auth and identity dependency providers.

Resolves the current user from JWT or API key, and provides guards
(require_auth, require_verified_email) used by protected routes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Annotated

import jwt as pyjwt
import structlog
from bson import ObjectId
from fastapi import Depends, Request

from dependencies.infra import get_db, get_settings
from errors import AuthenticationError, EmailNotVerifiedError, ForbiddenError
from infrastructure.crypto import hash_token
from infrastructure.logging import get_logger
from repositories.api_key_repository import ApiKeyRepository
from repositories.user_repository import UserRepository
from schemas.dto.requests.api_key import ApiKeyScope
from schemas.models.api_key import ApiKeyDoc

log = get_logger(__name__)


@dataclass
class CurrentUser:
    """Resolved identity after auth check.

    ``api_key_doc`` is set when the request was authenticated via API key
    (``Authorization: Bearer spoo_<raw>``).  It is ``None`` for JWT auth.
    Scope checks inspect ``api_key_doc.scopes`` when present, otherwise
    ``scopes`` (the JWT ``scp`` claim) when not None.
    """

    user_id: ObjectId
    email_verified: bool
    api_key_doc: ApiKeyDoc | None = field(default=None)
    amr: str = "pwd"
    # Scope slugs from the JWT "scp" claim (device-auth app tokens).
    # None = unrestricted interactive session; [] would mean "no scopes".
    scopes: list[str] | None = field(default=None)
    # Connected-app id from the JWT "app_id" claim (device auth flow).
    app_id: str | None = field(default=None)
    # Lowercased user email — consumed by FeatureFlagService's ALLOWLIST
    # rollout (allowlist_emails). Populated from the "email" claim on the
    # JWT path and from the owning UserDoc on the API-key path. None for
    # access tokens minted before the claim existed; those users match by
    # user_id only until their next token refresh.
    email: str | None = field(default=None)
    # UserDoc.plan value (e.g. "FREE") — consumed by FeatureFlagService's
    # TIER rollout via getattr(user, "tier"). Populated from the DB on the
    # API-key path and from the (future) "plan" claim on the JWT path.
    tier: str | None = field(default=None)


async def get_current_user(
    request: Request,
    db=Depends(get_db),
) -> CurrentUser | None:
    """Resolve the current user from the Authorization header or access_token cookie.

    Auth resolution order (mirrors the existing Flask implementation):
      1. Authorization: Bearer spoo_<raw>  →  API key path
      2. Authorization: Bearer <jwt>        →  JWT path
      3. access_token cookie               →  JWT path
      4. None                              →  anonymous

    Returns None for anonymous requests; never raises.
    """
    settings = get_settings(request)
    jwt_cfg = settings.jwt

    auth_header = request.headers.get("Authorization", "")
    token: str | None = None

    if auth_header.lower().startswith("bearer "):
        token = auth_header.split(" ", 1)[1].strip()

        # ── API key path ──────────────────────────────────────────────────────
        if token.startswith("spoo_"):
            raw = token[len("spoo_") :]
            token_hash = hash_token(raw)
            try:
                key = await ApiKeyRepository(db["api-keys"]).find_by_hash(token_hash)
            except Exception:
                return None

            if key is None or key.revoked:
                return None

            now = datetime.now(timezone.utc)
            if key.expires_at:
                exp = (
                    key.expires_at.replace(tzinfo=timezone.utc)
                    if key.expires_at.tzinfo is None
                    else key.expires_at
                )
                if exp <= now:
                    return None

            try:
                user = await UserRepository(db["users"]).find_by_id(key.user_id)
            except Exception:
                return None

            email_verified = user.email_verified if user else False
            structlog.contextvars.bind_contextvars(
                user_id=str(key.user_id), auth_method="api_key"
            )
            return CurrentUser(
                user_id=key.user_id,
                email_verified=email_verified,
                api_key_doc=key,
                # The owning UserDoc is already fetched above for
                # email_verified — no extra DB hit to carry the email.
                email=user.email.lower() if user and user.email else None,
                tier=user.plan.value if user and user.plan else None,
            )

    # ── JWT path ──────────────────────────────────────────────────────────────
    if not token:
        token = request.cookies.get("access_token")

    if not token:
        return None

    try:
        algorithm = "RS256" if jwt_cfg.use_rs256 else "HS256"
        verify_key = jwt_cfg.jwt_public_key if jwt_cfg.use_rs256 else jwt_cfg.jwt_secret
        claims = pyjwt.decode(
            token,
            verify_key,
            algorithms=[algorithm],
            issuer=jwt_cfg.jwt_issuer,
            audience=jwt_cfg.jwt_audience,
        )
        # Reject refresh tokens used as access tokens
        if claims.get("type") == "refresh":
            return None
        user_id = ObjectId(claims["sub"])
        email_verified = bool(claims.get("email_verified", False))
        amr = claims.get("amr", ["pwd"])[0]
        # Tolerant read — access tokens minted before the "email" claim
        # existed simply carry email=None (never an error). Fixed on the
        # user's next token refresh.
        raw_email = claims.get("email")
        email = (
            raw_email.strip().lower()
            if isinstance(raw_email, str) and raw_email.strip()
            else None
        )
        # Device-auth app tokens carry scp + app_id; session tokens carry
        # neither. A malformed scp claim fails closed (empty scope list)
        # rather than falling back to unrestricted.
        raw_scopes = claims.get("scp")
        scopes: list[str] | None = None
        if raw_scopes is not None:
            scopes = (
                [s for s in raw_scopes if isinstance(s, str)]
                if isinstance(raw_scopes, list)
                else []
            )
        structlog.contextvars.bind_contextvars(user_id=str(user_id), auth_method="jwt")
        return CurrentUser(
            user_id=user_id,
            email_verified=email_verified,
            amr=amr,
            email=email,
            # Not issued yet — the paid-plans launch adds the claim; TIER
            # flag rollouts become a pure data change at that point.
            tier=claims.get("plan"),
            scopes=scopes,
            app_id=claims.get("app_id"),
        )
    except Exception:
        return None


async def require_auth(
    user: CurrentUser | None = Depends(get_current_user),
) -> CurrentUser:
    """Raise 401 if the request is not authenticated."""
    if user is None:
        raise AuthenticationError("Authentication required")
    return user


async def require_verified_email(
    user: CurrentUser = Depends(require_auth),
) -> CurrentUser:
    """Raise 403 (EMAIL_NOT_VERIFIED) if the user's email is unverified."""
    if not user.email_verified:
        raise EmailNotVerifiedError("Email verification required")
    return user


async def require_jwt(
    user: CurrentUser = Depends(require_auth),
) -> CurrentUser:
    """Raise 403 unless the request comes from an interactive session.

    Rejects API keys AND scoped device-app tokens (``scp`` claim). Use on
    account-security surfaces — profile, app management, device revoke —
    where a delegated credential must never act.
    """
    if user.api_key_doc is not None:
        raise ForbiddenError("API keys cannot be used to manage API keys")
    if user.scopes is not None:
        raise ForbiddenError("This operation requires an interactive session")
    return user


async def require_jwt_verified(
    user: CurrentUser = Depends(require_jwt),
) -> CurrentUser:
    """JWT-only auth + verified email check."""
    if not user.email_verified:
        raise EmailNotVerifiedError("Email verification required")
    return user


def _granted_scopes(user: CurrentUser) -> set[str] | None:
    """The scope set a credential holds, or None for unrestricted sessions."""
    if user.api_key_doc is not None:
        return set(user.api_key_doc.scopes)
    if user.scopes is not None:
        return set(user.scopes)
    return None


def check_credential_scopes(
    user: CurrentUser | None, required_scopes: set[str]
) -> None:
    """Raise ForbiddenError if a scoped credential lacks a required scope.

    Fires for API keys (key scopes) and device-app tokens (``scp`` claim);
    interactive sessions and anonymous requests are not scope-restricted.
    A single match against ``required_scopes`` suffices (OR semantics).
    """
    if user is None:
        return
    granted = _granted_scopes(user)
    if granted is not None and not granted & required_scopes:
        raise ForbiddenError("Insufficient scope for this operation")


# Back-compat alias — the check now covers app tokens too.
check_api_key_scope = check_credential_scopes


# ── Named scope sets ─────────────────────────────────────────────────────────

STATS_SCOPES: set[str] = {
    ApiKeyScope.STATS_READ,
    ApiKeyScope.URLS_READ,
    ApiKeyScope.ADMIN_ALL,
}
URL_MANAGEMENT_SCOPES: set[str] = {ApiKeyScope.URLS_MANAGE, ApiKeyScope.ADMIN_ALL}
URL_READ_SCOPES: set[str] = {
    ApiKeyScope.URLS_MANAGE,
    ApiKeyScope.URLS_READ,
    ApiKeyScope.ADMIN_ALL,
}
SHORTEN_SCOPES: set[str] = {ApiKeyScope.SHORTEN_CREATE, ApiKeyScope.ADMIN_ALL}
REPORTS_SCOPES: set[str] = {ApiKeyScope.REPORTS_CREATE, ApiKeyScope.ADMIN_ALL}
DOMAIN_MANAGE_SCOPES: set[str] = {ApiKeyScope.DOMAINS_MANAGE, ApiKeyScope.ADMIN_ALL}
DOMAIN_READ_SCOPES: set[str] = {
    ApiKeyScope.DOMAINS_MANAGE,
    ApiKeyScope.DOMAINS_READ,
    ApiKeyScope.ADMIN_ALL,
}
# Deliberately NOT satisfied by admin:all: API keys can hold admin:all but
# must never manage keys, and app tokens declare keys:manage explicitly.
KEYS_MANAGE_SCOPES: set[str] = {ApiKeyScope.KEYS_MANAGE}


# ── Parameterised scope dependency factories ─────────────────────────────────


def require_scopes(scopes: set[str]):
    """Dependency factory: require_auth + API-key scope check.

    Moves scope enforcement into the dependency graph so route handlers
    receive an already-validated ``CurrentUser``.

    Usage::

        user: CurrentUser = Depends(require_scopes(URL_MANAGEMENT_SCOPES))
    """

    async def _dep(user: CurrentUser = Depends(require_auth)) -> CurrentUser:
        check_credential_scopes(user, scopes)
        return user

    return _dep


def require_session_or_scopes(scopes: set[str]):
    """Dependency factory: interactive session OR a credential holding *scopes*.

    Passes when the caller is an unrestricted session (JWT without ``scp``,
    no API key), or when the credential's scope set intersects *scopes*.
    Built for key management: API keys can never be created with
    ``keys:manage`` (see ALLOWED_SCOPES), so the anti-self-propagation
    guard holds while scoped app tokens that declare it get through.
    """

    async def _dep(user: CurrentUser = Depends(require_auth)) -> CurrentUser:
        granted = _granted_scopes(user)
        if granted is None:
            return user  # interactive session — unrestricted
        if not granted & scopes:
            raise ForbiddenError("Insufficient scope for this operation")
        return user

    return _dep


def optional_scopes(scopes: set[str]):
    """Dependency factory: get_current_user + optional API-key scope check.

    Does not require authentication; raises only when an API key is used
    and it lacks the required scope.

    Usage::

        user: Optional[CurrentUser] = Depends(optional_scopes(SHORTEN_SCOPES))
    """

    async def _dep(
        user: CurrentUser | None = Depends(get_current_user),
    ) -> CurrentUser | None:
        check_credential_scopes(user, scopes)
        return user

    return _dep


# ── Composed dependencies ────────────────────────────────────────────────────


def optional_scopes_verified(scopes: set[str]):
    """Like ``optional_scopes`` but requires email verification when authenticated.

    Anonymous requests pass through. Authenticated users without a verified
    email are rejected with ``EmailNotVerifiedError``.

    Use for optional-auth endpoints that create resources.
    """

    async def _dep(
        user: CurrentUser | None = Depends(optional_scopes(scopes)),
    ) -> CurrentUser | None:
        if user is not None and not user.email_verified:
            raise EmailNotVerifiedError("Email verification required")
        return user

    return _dep


def require_scopes_verified(scopes: set[str]):
    """``require_scopes`` plus email-verification gate.

    Use on protected create endpoints that accept BOTH JWT and API key auth.
    API key callers must also be email-verified (their underlying user must
    have verified the email at signup time).
    """

    async def _dep(
        user: CurrentUser = Depends(require_scopes(scopes)),
    ) -> CurrentUser:
        if not user.email_verified:
            raise EmailNotVerifiedError("Email verification required")
        return user

    return _dep


# ── Named dependency instances ────────────────────────────────────────────────

# Key management: interactive session OR a credential holding keys:manage.
# Module-level singletons so routes share one dependency object and tests
# can override it.
require_keys_access = require_session_or_scopes(KEYS_MANAGE_SCOPES)


async def require_keys_access_verified(
    user: CurrentUser = Depends(require_keys_access),
) -> CurrentUser:
    """Key-management access + verified email (for key creation)."""
    if not user.email_verified:
        raise EmailNotVerifiedError("Email verification required")
    return user


# ── Annotated type aliases — community-standard Depends shortcuts ─────────────

AuthUser = Annotated[CurrentUser, Depends(require_auth)]
VerifiedUser = Annotated[CurrentUser, Depends(require_verified_email)]
OptionalUser = Annotated[CurrentUser | None, Depends(get_current_user)]
JwtUser = Annotated[CurrentUser, Depends(require_jwt)]
JwtVerifiedUser = Annotated[CurrentUser, Depends(require_jwt_verified)]
KeysAccessUser = Annotated[CurrentUser, Depends(require_keys_access)]
KeysAccessVerifiedUser = Annotated[CurrentUser, Depends(require_keys_access_verified)]
