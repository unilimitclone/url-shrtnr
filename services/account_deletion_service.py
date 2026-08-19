"""Account deletion requests + grace-period restore (GDPR Art. 17 intake).

The interactive half of account deletion: ``request_deletion`` flips an
ACTIVE account to PENDING_DELETION after re-authentication, ``restore``
cancels a pending deletion with credentials. The destructive half — the
cascade that actually erases data — lives in ``AccountErasureService``,
driven by the scheduled sweep once ``purge_after`` passes.

Token revocation note: session and device refresh tokens are stateless
JWTs with no server-side store, so there is nothing to delete here.
Every refresh path (``CredentialService.refresh_token``, the device
flows) re-fetches the user and requires ACTIVE status, so the flip to
PENDING_DELETION kills rotation immediately; outstanding ACCESS tokens
live to their short expiry — same caveat as any status change.
"""

from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

from errors import ConflictError, ForbiddenError, NotFoundError
from infrastructure.crypto import verify_password
from infrastructure.logging import get_logger
from schemas.models.user import UserDoc, UserStatus
from services.account_erasure_service import ErasureMailer, NoopErasureMailer

if TYPE_CHECKING:
    from bson import ObjectId

    from repositories.user_repository import UserRepository

log = get_logger(__name__)

# One message for every re-auth failure — which credential was wrong (or
# missing) must not leak to a stolen-session attacker probing the account.
_REAUTH_FAILED = "re-authentication failed"

# One message for every restore failure — wrong password, unknown email,
# and not-pending all answer identically (no account enumeration).
_RESTORE_FAILED = "unable to restore account"


class AccountDeletionService:
    """Deletion intake and grace-period restore for one account.

    Args:
        user_repo:  Repository for the ``users`` collection.
        mailer:     Deletion lifecycle mail (Noop until Task 5 wires
                    the real templates).
        grace_days: Days between the request and the erasure sweep
                    picking the account up (``settings.account_deletion_grace_days``).
    """

    def __init__(
        self,
        user_repo: UserRepository,
        *,
        mailer: ErasureMailer | None = None,
        grace_days: int = 7,
    ) -> None:
        self._user_repo = user_repo
        self._mailer = mailer or NoopErasureMailer()
        self._grace_days = grace_days

    async def request_deletion(
        self,
        user_id: ObjectId,
        *,
        password: str | None,
        confirm_email: str | None,
    ) -> datetime:
        """Flip the account to PENDING_DELETION. Returns the purge deadline.

        Raises:
            NotFoundError:  The authenticated user no longer exists.
            ConflictError:  Deletion already requested (409).
            ForbiddenError: Re-authentication failed (403) — uniform
                message regardless of which credential was wrong.
        """
        svc_log = log.bind(op="account.request_deletion")

        user = await self._user_repo.find_by_id(user_id)
        if user is None:
            raise NotFoundError("user not found")
        if user.status == UserStatus.PENDING_DELETION:
            raise ConflictError("account deletion already requested")

        self._verify_reauth(user, password, confirm_email)

        flipped = await self._user_repo.mark_pending_deletion(user.id, self._grace_days)
        if not flipped:
            # Lost a race with a concurrent request (the guarded transition
            # matches ACTIVE only) — same answer as the pre-check.
            raise ConflictError("account deletion already requested")

        # Read back the stored deadline — the repo computed it, and the
        # response must echo exactly what the sweep will honour.
        updated = await self._user_repo.find_by_id(user.id)
        if updated is None or updated.purge_after is None:
            # The flip succeeded, so this only happens on a pathological
            # race with the sweep; recompute the same deadline.
            purge_after = datetime.now(timezone.utc) + timedelta(days=self._grace_days)
        else:
            purge_after = updated.purge_after

        svc_log.info(
            "account_deletion_requested",
            user_id=str(user.id),
            grace_days=self._grace_days,
        )
        await self._notify_requested(user.email, purge_after)
        return purge_after

    async def restore(self, email: str, password: str) -> None:
        """Cancel a pending deletion with email + password credentials.

        OAuth-only accounts (no password) cannot restore here — the
        frontend routes them through the OAuth restore flow instead.

        Raises:
            ForbiddenError: Uniform 403 for wrong credentials, unknown
                email, and accounts not pending deletion — the endpoint
                must not become an account-state oracle.
        """
        svc_log = log.bind(op="account.restore")

        user = await self._user_repo.find_by_email(email.strip().lower())
        if user is None or not user.password_hash:
            svc_log.info("account_restore_failed", reason="invalid_credentials")
            raise ForbiddenError(_RESTORE_FAILED)
        if not verify_password(password, user.password_hash):
            svc_log.info(
                "account_restore_failed",
                reason="invalid_credentials",
                user_id=str(user.id),
            )
            raise ForbiddenError(_RESTORE_FAILED)
        if not await self._user_repo.restore(user.id):
            # Not PENDING_DELETION (or a race restored/purged it first).
            svc_log.info(
                "account_restore_failed",
                reason="not_pending",
                user_id=str(user.id),
            )
            raise ForbiddenError(_RESTORE_FAILED)

        svc_log.info("account_restored", user_id=str(user.id))

    # ── Internal ────────────────────────────────────────────────────────

    @staticmethod
    def _verify_reauth(
        user: UserDoc, password: str | None, confirm_email: str | None
    ) -> None:
        """Prove the request comes from the account owner, not a session.

        Password accounts re-auth with the password ONLY — accepting the
        typed-email fallback there would let a hijacked session skip the
        password. OAuth-only accounts type their exact account email.
        """
        if user.password_set and user.password_hash:
            if password and verify_password(password, user.password_hash):
                return
        else:
            supplied = (confirm_email or "").encode()
            if secrets.compare_digest(supplied, user.email.encode()):
                return
        log.info(
            "account_deletion_reauth_failed",
            op="account.request_deletion",
            user_id=str(user.id),
            has_password=user.password_set,
        )
        raise ForbiddenError(_REAUTH_FAILED)

    async def _notify_requested(self, email: str, purge_after: datetime) -> None:
        """Best-effort grace-period notice — log-and-continue on failure.

        The deletion request must not fail on a mail outage; the user
        already sees the deadline in the response. Never log the address.
        """
        try:
            await self._mailer.send_deletion_requested(email, purge_after)
        except Exception as exc:
            log.warning("account_deletion_mail_failed", error=str(exc))
