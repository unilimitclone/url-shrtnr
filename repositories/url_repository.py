"""
Repository for the `urlsV2` MongoDB collection.

All methods are async and return typed Pydantic document models.
Errors are handled by BaseRepository — domain methods delegate to
shared CRUD helpers.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TypedDict

from bson import ObjectId
from pymongo.errors import PyMongoError

from infrastructure.logging import get_logger
from repositories.base import BaseRepository
from schemas.models.url import UrlStatus, UrlV2Doc

log = get_logger(__name__)


class StatsPrivacyInfo(TypedDict):
    """Return type for check_stats_privacy."""

    exists: bool
    private: bool
    owner_id: str | None


class UrlRepository(BaseRepository[UrlV2Doc]):
    async def find_by_alias(self, alias: str, domain: str) -> UrlV2Doc | None:
        """Find a URL by ``(alias, domain)``."""
        return await self._find_one({"alias": alias, "domain": domain})

    async def find_by_id(self, url_id: ObjectId) -> UrlV2Doc | None:
        """Find a URL document by its ObjectId."""
        return await self._find_one({"_id": url_id})

    async def find_by_id_and_owner(
        self, url_id: ObjectId, owner_id: ObjectId
    ) -> UrlV2Doc | None:
        """Find a URL by ObjectId, scoped to its owner.

        Ownership lives IN the query so a foreign id answers exactly like a
        missing one — read surfaces must not confirm that someone else's
        URL exists.
        """
        return await self._find_one({"_id": url_id, "owner_id": owner_id})

    async def find_by_alias_and_owner(
        self, alias: str, domain: str, owner_id: ObjectId
    ) -> UrlV2Doc | None:
        """Find a URL by ``(alias, domain)``, scoped to its owner.

        Same no-existence-oracle shape as ``find_by_id_and_owner`` — a
        foreign link is indistinguishable from a missing one.
        """
        return await self._find_one(
            {"alias": alias, "domain": domain, "owner_id": owner_id}
        )

    async def insert(self, doc: dict) -> ObjectId:
        """Insert a new URL document. Returns the inserted _id."""
        return await self._insert(doc)

    async def update(self, url_id: ObjectId, update_ops: dict) -> bool:
        """Apply a MongoDB update document to a URL.

        Returns True if the document was matched (and potentially modified).
        """
        return await self._update({"_id": url_id}, update_ops)

    async def delete(self, url_id: ObjectId) -> bool:
        """Hard-delete a URL document. Returns True if a document was deleted."""
        return await self._delete({"_id": url_id})

    async def record_meta_image_validation(
        self, url_id: ObjectId, image_url: str, meta: dict
    ) -> bool:
        """CAS-write async image-validation results.

        Filtering on the CURRENT image URL means a user edit that raced the
        validator makes this a no-op instead of clobbering the new image.
        """
        return await self._update(
            {"_id": url_id, "meta_tags.image": image_url},
            {"$set": {"meta_tags.image_meta": meta}},
        )

    async def clear_meta_image(self, url_id: ObjectId, image_url: str) -> bool:
        """CAS-clear an image that failed async validation."""
        return await self._update(
            {"_id": url_id, "meta_tags.image": image_url},
            {"$set": {"meta_tags.image": None, "meta_tags.image_meta": None}},
        )

    async def list_aliases_by_owner_and_domain(
        self, owner_id: ObjectId, domain: str
    ) -> list[str]:
        """Return all aliases owned by *owner_id* under *domain*.

        Used by bulk-delete to drive cache invalidation. Two-step (list then
        delete) trades atomicity for explicit cache cleanup — a cache miss
        post-delete is correct behavior anyway.
        """
        try:
            cursor = self._col.find(
                {"owner_id": owner_id, "domain": domain},
                projection={"alias": 1, "_id": 0},
            )
            docs = await cursor.to_list(length=None)
            return [d["alias"] for d in docs if "alias" in d]
        except PyMongoError as exc:
            log.error(
                "repo_list_aliases_failed",
                collection=self._collection_name,
                error=str(exc),
            )
            raise

    async def delete_many_by_owner_and_domain(
        self, owner_id: ObjectId, domain: str
    ) -> int:
        """Bulk-delete all URLs owned by *owner_id* under *domain*.

        Both filters required defensively — a missing or empty arg here would
        silently delete more than intended.
        """
        if not owner_id or not domain:
            raise ValueError("owner_id and domain are both required for bulk delete")
        try:
            result = await self._col.delete_many(
                {"owner_id": owner_id, "domain": domain}
            )
            return int(result.deleted_count or 0)
        except PyMongoError as exc:
            log.error(
                "repo_delete_many_failed",
                collection=self._collection_name,
                error=str(exc),
            )
            raise

    async def find_by_ids_and_owner(
        self, url_ids: list[ObjectId], owner_id: ObjectId
    ) -> list[UrlV2Doc]:
        """Fetch the subset of *url_ids* owned by *owner_id*.

        The ownership-scoped batch fetch behind /urls/bulk/*: ownership is
        enforced IN the query so a foreign id simply doesn't come back —
        never as a post-fetch compare (fail closed). Both filters required
        defensively, mirroring the bulk-delete guard below.
        """
        if not url_ids or not owner_id:
            raise ValueError("url_ids and owner_id are both required for bulk fetch")
        try:
            cursor = self._col.find({"_id": {"$in": url_ids}, "owner_id": owner_id})
            docs = await cursor.to_list(length=None)
            return [UrlV2Doc.from_mongo(doc) for doc in docs]
        except PyMongoError as exc:
            log.error(
                "repo_find_by_ids_failed",
                collection=self._collection_name,
                error=str(exc),
            )
            raise

    async def delete_by_ids_and_owner(
        self, url_ids: list[ObjectId], owner_id: ObjectId
    ) -> int:
        """Bulk-delete exactly *url_ids* if owned by *owner_id*.

        Both filters required defensively — the compound filter keeps the
        write fail-closed even if a caller's pre-fetch went stale.
        """
        if not url_ids or not owner_id:
            raise ValueError("url_ids and owner_id are both required for bulk delete")
        try:
            result = await self._col.delete_many(
                {"_id": {"$in": url_ids}, "owner_id": owner_id}
            )
            return int(result.deleted_count or 0)
        except PyMongoError as exc:
            log.error(
                "repo_delete_many_failed",
                collection=self._collection_name,
                error=str(exc),
            )
            raise

    async def update_by_ids_and_owner(
        self, url_ids: list[ObjectId], owner_id: ObjectId, set_ops: dict
    ) -> int:
        """Apply one ``$set`` to exactly *url_ids* if owned by *owner_id*.

        Same defensive posture as the bulk delete above; *set_ops* is the
        bare field map (the ``$set`` wrapper is applied here).
        """
        if not url_ids or not owner_id:
            raise ValueError("url_ids and owner_id are both required for bulk update")
        if not set_ops:
            raise ValueError("set_ops must not be empty")
        try:
            result = await self._col.update_many(
                {"_id": {"$in": url_ids}, "owner_id": owner_id}, {"$set": set_ops}
            )
            return int(result.modified_count or 0)
        except PyMongoError as exc:
            log.error(
                "repo_update_many_failed",
                collection=self._collection_name,
                error=str(exc),
            )
            raise

    async def check_alias_exists(self, alias: str, domain: str) -> bool:
        """Return True if the alias is taken under the given domain namespace."""
        doc = await self._find_one_raw({"alias": alias, "domain": domain}, {"_id": 1})
        return doc is not None

    async def increment_clicks(
        self,
        url_id: ObjectId,
        last_click_time: datetime | None = None,
        increment: int = 1,
    ) -> None:
        """Atomically increment total_clicks and update last_click timestamp."""
        click_time = last_click_time or datetime.now(timezone.utc)
        await self._update(
            {"_id": url_id},
            {
                "$inc": {"total_clicks": increment},
                "$set": {"last_click": click_time},
            },
        )

    async def expire_if_max_clicks(self, url_id: ObjectId, max_clicks: int) -> bool:
        """Conditionally expire the URL if total_clicks >= max_clicks.

        This is an atomic conditional update — not a read-then-write.
        Returns True only if the URL was actually expired (status changed),
        not if it was already EXPIRED. Uses ``modified_count`` to avoid
        duplicate expiration side-effects.
        """
        return await self._update_modified(
            {"_id": url_id, "total_clicks": {"$gte": max_clicks}},
            {"$set": {"status": UrlStatus.EXPIRED}},
        )

    async def expire_if_time_reached(self, url_id: ObjectId) -> bool:
        """Conditionally expire the URL if its expire_after has passed.

        Atomic conditional update mirroring ``expire_if_max_clicks`` —
        matches only ACTIVE docs so BLOCKED/INACTIVE are never clobbered.
        Returns True only if this call performed the flip (modified_count).
        ``$lte`` on a date never matches null/missing (BSON type
        bracketing), so no explicit null guard is needed.
        """
        return await self._update_modified(
            {
                "_id": url_id,
                "status": UrlStatus.ACTIVE,
                "expire_after": {"$lte": datetime.now(timezone.utc)},
            },
            {"$set": {"status": UrlStatus.EXPIRED}},
        )

    async def find_by_owner(
        self,
        query: dict,
        sort_field: str,
        sort_order: int,
        skip: int,
        limit: int,
    ) -> list[UrlV2Doc]:
        """Return a page of UrlV2Doc models matching *query*.

        The query must already include the owner_id filter (built by the
        service layer).
        """
        try:
            cursor = (
                self._col.find(query)
                .sort(sort_field, sort_order)
                .skip(skip)
                .limit(limit)
            )
            docs = await cursor.to_list(length=limit)
            return [UrlV2Doc.from_mongo(d) for d in docs]  # type: ignore[misc]
        except PyMongoError as exc:
            log.error(
                "repo_find_by_owner_failed",
                collection=self._collection_name,
                error=str(exc),
                error_type=type(exc).__name__,
            )
            raise

    async def count_by_query(self, query: dict) -> int:
        """Count documents matching query."""
        return await self._count(query)

    async def check_stats_privacy(self, alias: str) -> StatsPrivacyInfo:
        """Return privacy metadata for a URL alias.

        Currently unscoped — stats route only operates on system-default
        shorts. Scope by domain when stats becomes domain-aware.
        """
        doc = await self._find_one_raw(
            {"alias": alias},
            {"private_stats": 1, "owner_id": 1},
        )
        if not doc:
            return {"exists": False, "private": False, "owner_id": None}
        return {
            "exists": True,
            "private": bool(doc.get("private_stats", False)),
            "owner_id": str(doc["owner_id"]) if doc.get("owner_id") else None,
        }
