"""
Repository for the `users` MongoDB collection.

All methods are async and return typed Pydantic document models (UserDoc).
Errors are handled by BaseRepository.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from bson import ObjectId
from pymongo.errors import PyMongoError

from infrastructure.logging import get_logger
from repositories.base import BaseRepository
from schemas.models.user import UserDoc, UserStatus

log = get_logger(__name__)


class UserRepository(BaseRepository[UserDoc]):
    async def find_by_email(self, email: str) -> UserDoc | None:
        """Find a user by email address."""
        return await self._find_one({"email": email})

    async def find_by_id(self, user_id: ObjectId) -> UserDoc | None:
        """Find a user by ObjectId."""
        return await self._find_one({"_id": user_id})

    async def find_by_oauth_provider(
        self, provider: str, provider_user_id: str
    ) -> UserDoc | None:
        """Find a user by their OAuth provider and provider-issued user ID.

        Uses ``$elemMatch`` to ensure both fields match the same array
        element — without it, MongoDB can satisfy each condition from
        different elements when a user has multiple linked providers.
        """
        return await self._find_one(
            {
                "auth_providers": {
                    "$elemMatch": {
                        "provider": provider,
                        "provider_user_id": provider_user_id,
                    }
                }
            }
        )

    async def create(self, user_data: dict) -> ObjectId:
        """Insert a new user document. Returns the inserted _id."""
        return await self._insert(user_data)

    async def update(self, user_id: ObjectId, update_ops: dict) -> bool:
        """Apply a MongoDB update document to a user.

        Returns True if the document was matched.
        """
        return await self._update({"_id": user_id}, update_ops)

    async def complete_onboarding(
        self, user_id: ObjectId, when: datetime, heard_from: str | None
    ) -> bool:
        """Stamp ``onboarded_at`` (and HDYHAU) — first completion wins.

        The filter matches only while ``onboarded_at`` is null, so repeat
        calls are no-ops and can never overwrite the original timestamp or
        attribution. Returns True when THIS call did the stamping.
        """
        ops: dict = {"onboarded_at": when}
        if heard_from:
            ops["heard_from"] = heard_from
        return await self._update(
            {"_id": user_id, "onboarded_at": None},
            {"$set": ops},
        )

    async def mark_pending_deletion(self, user_id: ObjectId, grace_days: int) -> bool:
        """Flip an ACTIVE account to PENDING_DELETION with a purge deadline.

        Guarded transition — the filter matches ACTIVE only, so a repeat
        request (or one against an INACTIVE account) is a no-op. Returns
        True only when THIS call performed the flip.
        """
        now = datetime.now(timezone.utc)
        return await self._update_modified(
            {"_id": user_id, "status": UserStatus.ACTIVE.value},
            {
                "$set": {
                    "status": UserStatus.PENDING_DELETION.value,
                    "deletion_requested_at": now,
                    "purge_after": now + timedelta(days=grace_days),
                }
            },
        )

    async def restore(self, user_id: ObjectId) -> bool:
        """Cancel a pending deletion — PENDING_DELETION back to ACTIVE.

        Guarded like ``mark_pending_deletion``: only a PENDING_DELETION doc
        matches, so restoring an ACTIVE (or already-purged) account returns
        False. Clears both deletion timestamps.
        """
        return await self._update_modified(
            {"_id": user_id, "status": UserStatus.PENDING_DELETION.value},
            {
                "$set": {"status": UserStatus.ACTIVE.value},
                "$unset": {"deletion_requested_at": "", "purge_after": ""},
            },
        )

    async def find_purge_due(self, now: datetime, limit: int) -> list[UserDoc]:
        """Return pending-deletion users whose purge deadline has passed.

        Oldest deadline first, capped at *limit* — the erasure sweep's whole
        query shape, served by the ``pending_deletion_sweep`` partial index.
        """
        try:
            cursor = (
                self._col.find(
                    {
                        "status": UserStatus.PENDING_DELETION.value,
                        "purge_after": {"$lte": now},
                    }
                )
                .sort("purge_after", 1)
                .limit(limit)
            )
            docs = await cursor.to_list(length=limit)
            return [UserDoc.from_mongo(d) for d in docs]  # type: ignore[misc]
        except PyMongoError as exc:
            log.error(
                "repo_find_purge_due_failed",
                collection=self._collection_name,
                error=str(exc),
                error_type=type(exc).__name__,
            )
            raise

    async def delete_hard(self, user_id: ObjectId) -> bool:
        """Permanently delete the user document. Returns True if removed.

        The erasure cascade's LAST step — every satellite collection must be
        cleaned first, so a crash anywhere re-queues the user for the next
        sweep instead of orphaning data.
        """
        return await self._delete({"_id": user_id})
