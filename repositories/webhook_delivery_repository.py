"""Repository for the ``webhook-deliveries`` collection.

Owns the executor's claim semantics: ``claim_due`` is an atomic
``find_one_and_update`` (claim = lease via ``claimed_until``), which is
what makes N concurrent executors safe with no scheduler infrastructure
beyond Mongo itself. The claim query is stateless over
``next_attempt_at``, so process restarts self-heal on the first loop.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from bson import ObjectId
from pymongo import ReturnDocument

from repositories.base import BaseRepository
from schemas.enums.webhook import DeliveryStatus
from schemas.models.webhook import DeliveryAttempt, WebhookDeliveryDoc


class WebhookDeliveryRepository(BaseRepository[WebhookDeliveryDoc]):
    async def insert_many_rows(self, rows: list[dict]) -> None:
        if not rows:
            return
        await self._col.insert_many(rows)

    async def insert_row(self, row: dict) -> ObjectId:
        return await self._insert(row)

    async def find_by_id(self, delivery_id: ObjectId) -> WebhookDeliveryDoc | None:
        return await self._find_one({"_id": delivery_id})

    async def find_owned(
        self, delivery_id: ObjectId, user_id: ObjectId
    ) -> WebhookDeliveryDoc | None:
        return await self._find_one({"_id": delivery_id, "user_id": user_id})

    async def count_pending(self, endpoint_id: ObjectId) -> int:
        return await self._count(
            {"endpoint_id": endpoint_id, "status": DeliveryStatus.PENDING.value}
        )

    async def list_by_endpoint(
        self,
        endpoint_id: ObjectId,
        *,
        page: int,
        page_size: int,
        status: DeliveryStatus | None = None,
    ) -> tuple[list[WebhookDeliveryDoc], int]:
        query: dict = {"endpoint_id": endpoint_id}
        if status is not None:
            query["status"] = status.value
        total = await self._count(query)
        cursor = (
            self._col.find(query)
            .sort("created_at", -1)
            .skip((page - 1) * page_size)
            .limit(page_size)
        )
        docs = await cursor.to_list(length=page_size)
        return [WebhookDeliveryDoc.from_mongo(d) for d in docs], total

    async def delete_by_user(self, user_id: ObjectId) -> int:
        """Delete every delivery row for the user (account erasure).

        Returns the number of documents deleted.
        """
        return await self._delete_many({"user_id": user_id})

    # ── Executor surface ─────────────────────────────────────────────────

    async def claim_due(self, *, lease_seconds: int = 60) -> WebhookDeliveryDoc | None:
        """Atomically claim one due delivery, or None when nothing is due.

        A crashed executor's claim expires with its lease — rows are never
        stranded.
        """
        now = datetime.now(timezone.utc)
        doc = await self._col.find_one_and_update(
            {
                "status": DeliveryStatus.PENDING.value,
                "next_attempt_at": {"$lte": now},
                "$or": [
                    {"claimed_until": None},
                    {"claimed_until": {"$lte": now}},
                ],
            },
            {"$set": {"claimed_until": now + timedelta(seconds=lease_seconds)}},
            sort=[("next_attempt_at", 1)],
            return_document=ReturnDocument.AFTER,
        )
        return WebhookDeliveryDoc.from_mongo(doc)

    async def set_rendered_body(self, delivery_id: ObjectId, body: str) -> None:
        """First attempt only — the body is frozen across retries."""
        await self._update(
            {"_id": delivery_id, "rendered_body": None},
            {"$set": {"rendered_body": body}},
        )

    async def record_attempt_and_reschedule(
        self, delivery_id: ObjectId, attempt: DeliveryAttempt, next_attempt_at: datetime
    ) -> None:
        await self._update(
            {"_id": delivery_id},
            {
                "$push": {"attempts": attempt.model_dump()},
                "$inc": {"attempt_count": 1},
                "$set": {"next_attempt_at": next_attempt_at, "claimed_until": None},
            },
        )

    async def record_attempt_and_finish(
        self, delivery_id: ObjectId, attempt: DeliveryAttempt, status: DeliveryStatus
    ) -> None:
        await self._update(
            {"_id": delivery_id},
            {
                "$push": {"attempts": attempt.model_dump()},
                "$inc": {"attempt_count": 1},
                "$set": {
                    "status": status.value,
                    "completed_at": datetime.now(timezone.utc),
                    "next_attempt_at": None,
                    "claimed_until": None,
                },
            },
        )

    async def defer(self, delivery_id: ObjectId, *, delay_seconds: int) -> None:
        """Push a delivery back without recording an attempt — used while
        its endpoint is paused. Not a retry: the ladder is untouched."""
        await self._update(
            {"_id": delivery_id},
            {
                "$set": {
                    "next_attempt_at": datetime.now(timezone.utc)
                    + timedelta(seconds=delay_seconds),
                    "claimed_until": None,
                }
            },
        )

    async def mark_failed(self, delivery_id: ObjectId, reason: str) -> None:
        """Terminal failure without an HTTP attempt (endpoint inactive,
        event row TTL-expired)."""
        await self._update(
            {"_id": delivery_id},
            {
                "$inc": {"attempt_count": 1},
                "$set": {
                    "status": DeliveryStatus.FAILED.value,
                    "completed_at": datetime.now(timezone.utc),
                    "next_attempt_at": None,
                    "claimed_until": None,
                },
                "$push": {
                    "attempts": DeliveryAttempt(
                        attempted_at=datetime.now(timezone.utc), error=reason
                    ).model_dump()
                },
            },
        )
