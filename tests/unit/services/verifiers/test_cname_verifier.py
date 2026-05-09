"""Unit tests for CnameVerifier."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import dns.exception
import dns.resolver
import pytest

from services.verifiers.cname_verifier import CnameVerifier


def _cname_answer(*targets: str) -> list[MagicMock]:
    """Build a fake dnspython CNAME rrset (list of rdata-like objects)."""
    rrs = []
    for t in targets:
        r = MagicMock()
        r.target = t
        rrs.append(r)
    return rrs


class TestCnameVerifier:
    @pytest.mark.asyncio
    async def test_verified_when_target_matches(self):
        v = CnameVerifier("custom.spoo.me")
        with patch(
            "services.verifiers.cname_verifier.dns.asyncresolver.resolve",
            new=AsyncMock(return_value=_cname_answer("custom.spoo.me.")),
        ):
            r = await v.verify("links.example.com")
        assert r.verified is True

    @pytest.mark.asyncio
    async def test_target_compared_case_insensitively(self):
        v = CnameVerifier("Custom.Spoo.Me")
        with patch(
            "services.verifiers.cname_verifier.dns.asyncresolver.resolve",
            new=AsyncMock(return_value=_cname_answer("CUSTOM.SPOO.ME.")),
        ):
            r = await v.verify("links.example.com")
        assert r.verified is True

    @pytest.mark.asyncio
    async def test_mismatch_returns_failure_with_reason(self):
        v = CnameVerifier("custom.spoo.me")
        with patch(
            "services.verifiers.cname_verifier.dns.asyncresolver.resolve",
            new=AsyncMock(return_value=_cname_answer("evil.example.com.")),
        ):
            r = await v.verify("links.example.com")
        assert r.verified is False
        assert "evil.example.com" in r.reason
        assert "custom.spoo.me" in r.reason

    @pytest.mark.asyncio
    async def test_nxdomain_returns_failure(self):
        v = CnameVerifier("custom.spoo.me")
        with patch(
            "services.verifiers.cname_verifier.dns.asyncresolver.resolve",
            new=AsyncMock(side_effect=dns.resolver.NXDOMAIN()),
        ):
            r = await v.verify("nope.example.com")
        assert r.verified is False
        assert "NXDOMAIN" in r.reason

    @pytest.mark.asyncio
    async def test_no_answer_includes_target_in_message(self):
        v = CnameVerifier("custom.spoo.me")
        with patch(
            "services.verifiers.cname_verifier.dns.asyncresolver.resolve",
            new=AsyncMock(side_effect=dns.resolver.NoAnswer()),
        ):
            r = await v.verify("links.example.com")
        assert r.verified is False
        assert "custom.spoo.me" in r.reason

    @pytest.mark.asyncio
    async def test_timeout_returns_failure(self):
        v = CnameVerifier("custom.spoo.me")
        with patch(
            "services.verifiers.cname_verifier.dns.asyncresolver.resolve",
            new=AsyncMock(side_effect=asyncio.TimeoutError()),
        ):
            r = await v.verify("links.example.com")
        assert r.verified is False
        assert "timed out" in r.reason

    @pytest.mark.asyncio
    async def test_generic_dns_exception_swallowed(self):
        v = CnameVerifier("custom.spoo.me")

        class WeirdError(dns.exception.DNSException):
            pass

        with patch(
            "services.verifiers.cname_verifier.dns.asyncresolver.resolve",
            new=AsyncMock(side_effect=WeirdError("something else")),
        ):
            r = await v.verify("links.example.com")
        assert r.verified is False
