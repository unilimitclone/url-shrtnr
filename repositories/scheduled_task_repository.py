"""Repository for the ``scheduled_tasks`` collection.

Owns the runner's claim semantics: ``claim_due`` is the same atomic
``find_one_and_update`` lease as the webhook delivery executor, which is
what makes concurrent runners (worker + embedded app during a deploy
overlap) safe with no scheduler infrastructure beyond Mongo itself. The
claim query is stateless over ``next_run_at``, so restarts self-heal and an
overdue task runs exactly once on the first loop after boot.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from pymongo import ReturnDocument

from repositories.base import BaseRepository
from schemas.models.scheduled_task import ScheduledTaskDoc, TaskRunResult


class ScheduledTaskRepository(BaseRepository[ScheduledTaskDoc]):
    async def ensure_task(
        self,
        name: str,
        *,
        schedule: str | None,
        enabled_default: bool,
        next_run_at: datetime | None,
    ) -> None:
        """Upsert the task doc. ``$setOnInsert`` only — runtime state
        (enabled, next_run_at, last_run) is never clobbered on an existing
        doc; schedule drift is handled by ``reconcile_schedule``."""
        await self._col.update_one(
            {"_id": name},
            {
                "$setOnInsert": {
                    "schedule": schedule,
                    "next_run_at": next_run_at,
                    "claimed_until": None,
                    "enabled": enabled_default,
                    "last_run": None,
                    "updated_at": datetime.now(timezone.utc),
                }
            },
            upsert=True,
        )

    async def reconcile_schedule(
        self, name: str, *, schedule: str | None, next_run_at: datetime | None
    ) -> bool:
        """Apply a code-side schedule change to the stored doc. Returns True
        when the stored schedule differed and was updated."""
        result = await self._col.update_one(
            {"_id": name, "schedule": {"$ne": schedule}},
            {
                "$set": {
                    "schedule": schedule,
                    "next_run_at": next_run_at,
                    "updated_at": datetime.now(timezone.utc),
                }
            },
        )
        return bool(result.modified_count)

    async def claim_due(self, *, lease_seconds: int) -> ScheduledTaskDoc | None:
        """Atomically claim one due task, or None when nothing is due.

        BSON type bracketing means a null ``next_run_at`` (manual-only,
        not invoked) never matches the ``$lte`` date comparison. A crashed
        runner's claim expires with its lease — tasks are never stranded.
        """
        now = datetime.now(timezone.utc)
        doc = await self._col.find_one_and_update(
            {
                "enabled": True,
                "next_run_at": {"$lte": now},
                "$or": [
                    {"claimed_until": None},
                    {"claimed_until": {"$lte": now}},
                ],
            },
            {"$set": {"claimed_until": now + timedelta(seconds=lease_seconds)}},
            sort=[("next_run_at", 1)],
            return_document=ReturnDocument.AFTER,
        )
        return ScheduledTaskDoc.from_mongo(doc)

    async def finish_run(
        self, name: str, *, result: TaskRunResult, next_run_at: datetime | None
    ) -> None:
        """Record the outcome, release the lease, arm the next occurrence."""
        await self._col.update_one(
            {"_id": name},
            {
                "$set": {
                    "last_run": result.model_dump(),
                    "next_run_at": next_run_at,
                    "claimed_until": None,
                    "updated_at": datetime.now(timezone.utc),
                }
            },
        )

    async def release_claim(self, name: str) -> None:
        """Release a claim without recording a run or re-arming — the
        yield path for a claimer that cannot execute the task."""
        await self._col.update_one(
            {"_id": name},
            {"$set": {"claimed_until": None}},
        )

    async def invoke_now(self, name: str) -> bool:
        """Run-now invocator. Any caller (ops tooling, tests, future HTTP
        endpoint) schedules an immediate run by arming next_run_at; the
        claim lease still dedupes against the cron path."""
        result = await self._col.update_one(
            {"_id": name},
            {"$set": {"next_run_at": datetime.now(timezone.utc)}},
        )
        return bool(result.modified_count)

    async def list_names(self) -> set[str]:
        docs = await self._col.find({}, {"_id": 1}).to_list(length=None)
        return {d["_id"] for d in docs}
