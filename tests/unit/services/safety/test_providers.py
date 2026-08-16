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


class TestFeedDomainProvider:
    @pytest.mark.asyncio
    async def test_host_hit_is_toxic(self):
        from services.safety.providers import FeedDomainProvider

        repo = AsyncMock()
        repo.contains = AsyncMock(return_value=True)
        provider = FeedDomainProvider(repo, feed="fishfish", reason_label="fishfish.gg")
        verdict = await provider.analyze("https://evil.com/x", "evil.com", "evil.com")
        assert verdict is not None
        assert verdict.tier == VerdictTier.TOXIC
        assert "fishfish.gg" in verdict.reason
        repo.contains.assert_awaited_once_with("fishfish", "evil.com")

    @pytest.mark.asyncio
    async def test_registrable_fallback_when_host_clean(self):
        from services.safety.providers import FeedDomainProvider

        repo = AsyncMock()
        repo.contains = AsyncMock(side_effect=[False, True])
        provider = FeedDomainProvider(repo, feed="fishfish", reason_label="fishfish.gg")
        verdict = await provider.analyze(
            "https://a.evil.com/x", "a.evil.com", "evil.com"
        )
        assert verdict is not None
        assert "evil.com" in verdict.reason

    @pytest.mark.asyncio
    async def test_miss_and_error_abstain(self):
        from services.safety.providers import FeedDomainProvider

        repo = AsyncMock()
        repo.contains = AsyncMock(return_value=False)
        provider = FeedDomainProvider(repo, feed="fishfish", reason_label="fishfish.gg")
        assert await provider.analyze("https://ok.com/x", "ok.com", "ok.com") is None

        repo.contains = AsyncMock(side_effect=RuntimeError("mongo down"))
        assert await provider.analyze("https://ok.com/x", "ok.com", "ok.com") is None


class TestWebRiskProvider:
    @staticmethod
    def _http(payload, status=200):
        from types import SimpleNamespace

        http = AsyncMock()
        http.get = AsyncMock(
            return_value=SimpleNamespace(status_code=status, json=lambda: payload)
        )
        return http

    @pytest.mark.asyncio
    async def test_threat_match_is_toxic(self):
        from services.safety.providers import WebRiskProvider

        http = self._http(
            {"threat": {"threatTypes": ["SOCIAL_ENGINEERING"], "expireTime": "x"}}
        )
        provider = WebRiskProvider(http, api_key="k123")
        verdict = await provider.analyze(
            "https://phish.com/x", "phish.com", "phish.com"
        )
        assert verdict is not None
        assert verdict.tier == VerdictTier.TOXIC
        assert "SOCIAL_ENGINEERING" in verdict.reason
        # Request carries the uri, both threat types, and the key as params.
        _, kwargs = http.get.await_args
        assert kwargs["params"]["uri"] == "https://phish.com/x"
        assert set(kwargs["params"]["threatTypes"]) == {
            "MALWARE",
            "SOCIAL_ENGINEERING",
        }

    @pytest.mark.asyncio
    async def test_empty_response_abstains(self):
        from services.safety.providers import WebRiskProvider

        provider = WebRiskProvider(self._http({}), api_key="k123")
        assert await provider.analyze("https://ok.com/x", "ok.com", "ok.com") is None

    @pytest.mark.asyncio
    async def test_http_error_and_exception_abstain(self):
        from services.safety.providers import WebRiskProvider

        provider = WebRiskProvider(self._http({}, status=429), api_key="k123")
        assert await provider.analyze("https://ok.com/x", "ok.com", "ok.com") is None

        http = AsyncMock()
        http.get = AsyncMock(side_effect=RuntimeError("boom"))
        provider = WebRiskProvider(http, api_key="k123")
        assert await provider.analyze("https://ok.com/x", "ok.com", "ok.com") is None
