"""Unit tests for the feed integrations (fishfish client + sync task)."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from services.safety.feeds import (
    FISHFISH_SYNC_TASK,
    FishFishClient,
    fishfish_sync_task,
)


def _http(payload, status=200) -> AsyncMock:
    http = AsyncMock()
    response = SimpleNamespace(
        status_code=status,
        json=lambda: payload,
        raise_for_status=lambda: None,
    )
    http.get = AsyncMock(return_value=response)
    return http


class TestFishFishClient:
    @pytest.mark.asyncio
    async def test_fetch_returns_string_domains(self):
        http = _http(["evil.com", "scam.net", 42, None])
        client = FishFishClient(http, api_url="https://api.fishfish.gg/v1/domains")
        assert await client.fetch_domains() == ["evil.com", "scam.net"]

    @pytest.mark.asyncio
    async def test_non_list_response_raises(self):
        http = _http({"error": "nope"})
        client = FishFishClient(http, api_url="https://api.fishfish.gg/v1/domains")
        with pytest.raises(ValueError, match="expected list"):
            await client.fetch_domains()


class TestFishFishSyncTask:
    def test_task_shape(self):
        task = fishfish_sync_task(AsyncMock(), AsyncMock())
        assert task.name == FISHFISH_SYNC_TASK
        assert task.schedule == "0 * * * *"

    @pytest.mark.asyncio
    async def test_sync_swaps_and_reports_counts(self):
        client = AsyncMock()
        client.fetch_domains = AsyncMock(return_value=[f"d{i}.com" for i in range(500)])
        repo = AsyncMock()
        repo.replace_feed = AsyncMock(return_value=(500, 12))

        detail = await fishfish_sync_task(client, repo).fn()

        repo.replace_feed.assert_awaited_once()
        assert detail == {"domains": 500, "purged": 12}

    @pytest.mark.asyncio
    async def test_tiny_download_keeps_previous_set(self):
        """A near-empty feed response is a bad download, not a mass
        delisting — the previous set must survive."""
        client = AsyncMock()
        client.fetch_domains = AsyncMock(return_value=["only.com"])
        repo = AsyncMock()

        detail = await fishfish_sync_task(client, repo).fn()

        repo.replace_feed.assert_not_awaited()
        assert detail["skipped"] == "below_sanity_floor"

    @pytest.mark.asyncio
    async def test_fetch_failure_propagates_to_task_result(self):
        """The scheduler records handler exceptions as status=error — the
        client's raise must reach it, not be swallowed here."""
        client = AsyncMock()
        client.fetch_domains = AsyncMock(side_effect=RuntimeError("feed down"))
        repo = AsyncMock()

        with pytest.raises(RuntimeError, match="feed down"):
            await fishfish_sync_task(client, repo).fn()
        repo.replace_feed.assert_not_awaited()
