"""
Repository for the `feature_flags` MongoDB collection.

Read-mostly. Mutations are rare and happen via direct mongosh edits during
rollouts (PR0 ships without an admin API). The ``upsert`` and ``list_all``
methods exist to support tests, internal scripts, and the lifespan-time
``ensure_feature_flag`` helper that registers known flags on boot.
"""

from __future__ import annotations

from datetime import datetime, timezone

from bson import ObjectId

from repositories.base import BaseRepository
from schemas.models.feature_flag import FeatureFlagDoc


class FeatureFlagRepository(BaseRepository[FeatureFlagDoc]):
    async def find_by_name(self, name: str) -> FeatureFlagDoc | None:
        """Return the flag doc by name, or None if not registered."""
        return await self._find_one({"name": name})

    async def upsert(self, name: str, fields: dict) -> ObjectId:
        """Insert or update a flag doc by name. Returns the doc's _id.

        Uses ``$setOnInsert`` for ``created_at`` so re-running the upsert
        does not overwrite the original creation timestamp. ``updated_at``
        is always refreshed.
        """
        now = datetime.now(timezone.utc)
        set_fields = {**fields, "updated_at": now}
        result = await self._col.update_one(
            {"name": name},
            {
                "$set": set_fields,
                "$setOnInsert": {"created_at": now, "name": name},
            },
            upsert=True,
        )
        if result.upserted_id is not None:
            return result.upserted_id
        # Existing doc — fetch its _id for the return contract.
        doc = await self._find_one_raw({"name": name}, {"_id": 1})
        if doc is None:  # pragma: no cover — race only possible if doc deleted mid-call
            raise RuntimeError(
                f"feature flag {name!r} vanished between upsert and read"
            )
        return doc["_id"]

    async def list_all(self) -> list[FeatureFlagDoc]:
        """Return all registered flags. Used by admin scripts + tests."""
        cursor = self._col.find({})
        docs = await cursor.to_list(length=None)
        return [
            FeatureFlagDoc.from_mongo(d)  # type: ignore[misc]
            for d in docs
        ]
