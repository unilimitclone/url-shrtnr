"""Unit tests for backfill_url_domain.

Covers the one-shot data migration: docs missing the ``domain`` field (or
holding the empty-string sentinel) get the system default; pre-filled docs
are untouched; idempotent on re-run.
"""

from unittest.mock import AsyncMock, MagicMock

import pytest

from infrastructure.bootstrap.url_domain_backfill import backfill_url_domain


def _db_with_collection(col: AsyncMock) -> MagicMock:
    db = MagicMock()
    db.__getitem__ = lambda self, name: col
    return db


class TestBackfillUrlDomain:
    @pytest.mark.asyncio
    async def test_filters_missing_or_empty_domain(self):
        col = AsyncMock()
        col.update_many = AsyncMock(return_value=MagicMock(modified_count=42))

        await backfill_url_domain(_db_with_collection(col), "spoo.me")

        # Filter must match BOTH "no domain field" and "empty string domain"
        # — pre-PR1 docs lack the field, but a partially-migrated DB may
        # have empty strings from a previous failed run.
        filter_doc, update_doc = col.update_many.call_args.args
        assert filter_doc == {
            "$or": [
                {"domain": {"$exists": False}},
                {"domain": ""},
            ]
        }
        assert update_doc == {"$set": {"domain": "spoo.me"}}

    @pytest.mark.asyncio
    async def test_returns_modified_count(self):
        col = AsyncMock()
        col.update_many = AsyncMock(return_value=MagicMock(modified_count=137))

        count = await backfill_url_domain(_db_with_collection(col), "spoo.me")

        assert count == 137

    @pytest.mark.asyncio
    async def test_idempotent_when_nothing_to_backfill(self):
        # Re-running on a fully-migrated DB is a cheap no-op.
        col = AsyncMock()
        col.update_many = AsyncMock(return_value=MagicMock(modified_count=0))

        count = await backfill_url_domain(_db_with_collection(col), "spoo.me")

        assert count == 0

    @pytest.mark.asyncio
    async def test_self_hoster_default_domain(self):
        # Self-hosters get THEIR fqdn written into the docs, not spoo.me.
        col = AsyncMock()
        col.update_many = AsyncMock(return_value=MagicMock(modified_count=10))

        await backfill_url_domain(_db_with_collection(col), "my.shortener.dev")

        update_doc = col.update_many.call_args.args[1]
        assert update_doc["$set"]["domain"] == "my.shortener.dev"
