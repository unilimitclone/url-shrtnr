"""Unit tests for the analysis providers."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from schemas.enums.safety import VerdictTier
from services.safety.providers import BlockedDomainProvider, BlockedPatternProvider


class TestBlockedDomainProvider:
    @pytest.mark.asyncio
    async def test_host_hit_is_toxic(self):
        repo = AsyncMock()
        repo.is_blocked = AsyncMock(return_value=True)
        verdict = await BlockedDomainProvider(repo).analyze(
            "https://evil.com/x", "evil.com", "evil.com"
        )
        assert verdict is not None
        assert verdict.tier == VerdictTier.TOXIC

    @pytest.mark.asyncio
    async def test_registrable_domain_hit_when_host_clean(self):
        repo = AsyncMock()
        repo.is_blocked = AsyncMock(side_effect=[False, True])
        verdict = await BlockedDomainProvider(repo).analyze(
            "https://sub.evil.com/x", "sub.evil.com", "evil.com"
        )
        assert verdict is not None
        assert "evil.com" in verdict.reason

    @pytest.mark.asyncio
    async def test_miss_abstains(self):
        repo = AsyncMock()
        repo.is_blocked = AsyncMock(return_value=False)
        assert (
            await BlockedDomainProvider(repo).analyze(
                "https://ok.com/x", "ok.com", "ok.com"
            )
            is None
        )

    @pytest.mark.asyncio
    async def test_repo_error_abstains(self):
        repo = AsyncMock()
        repo.is_blocked = AsyncMock(side_effect=RuntimeError("mongo down"))
        assert (
            await BlockedDomainProvider(repo).analyze(
                "https://ok.com/x", "ok.com", "ok.com"
            )
            is None
        )


class TestBlockedPatternProvider:
    @pytest.mark.asyncio
    async def test_pattern_match_is_toxic(self):
        repo = AsyncMock()
        repo.get_patterns = AsyncMock(return_value=[r"(?i)corr\.php"])
        verdict = await BlockedPatternProvider(repo, regex_timeout=0.2).analyze(
            "https://x.contabo.net/COR/corr.php", "x.contabo.net", "contabo.net"
        )
        assert verdict is not None
        assert verdict.tier == VerdictTier.TOXIC

    @pytest.mark.asyncio
    async def test_no_match_abstains(self):
        repo = AsyncMock()
        repo.get_patterns = AsyncMock(return_value=[r"(?i)corr\.php"])
        assert (
            await BlockedPatternProvider(repo, regex_timeout=0.2).analyze(
                "https://ok.com/x", "ok.com", "ok.com"
            )
            is None
        )

    @pytest.mark.asyncio
    async def test_repo_error_abstains(self):
        repo = AsyncMock()
        repo.get_patterns = AsyncMock(side_effect=RuntimeError("mongo down"))
        assert (
            await BlockedPatternProvider(repo, regex_timeout=0.2).analyze(
                "https://ok.com/x", "ok.com", "ok.com"
            )
            is None
        )
