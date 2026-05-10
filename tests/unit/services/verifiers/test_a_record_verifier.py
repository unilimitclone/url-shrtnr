"""Unit tests for ARecordVerifier."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import dns.exception
import dns.resolver
import pytest

from services.verifiers.a_record_verifier import ARecordVerifier


def _a_answer(*addrs: str) -> list[MagicMock]:
    return [MagicMock(address=a) for a in addrs]


class TestARecordVerifier:
    def test_rejects_empty_origin_list(self):
        with pytest.raises(ValueError):
            ARecordVerifier([])

    def test_strips_whitespace_in_origins(self):
        v = ARecordVerifier(["  1.2.3.4  ", "5.6.7.8"])
        # Field is private but we can verify behaviour via verify().
        assert v._origin_ipv4 == frozenset({"1.2.3.4", "5.6.7.8"})

    @pytest.mark.asyncio
    async def test_verified_when_any_a_matches(self):
        v = ARecordVerifier(["1.2.3.4", "5.6.7.8"])
        with patch(
            "services.verifiers.a_record_verifier.dns.asyncresolver.resolve",
            new=AsyncMock(return_value=_a_answer("9.9.9.9", "1.2.3.4")),
        ):
            r = await v.verify("acme.com")
        assert r.verified is True

    @pytest.mark.asyncio
    async def test_failure_lists_expected_origins(self):
        v = ARecordVerifier(["1.2.3.4"])
        with patch(
            "services.verifiers.a_record_verifier.dns.asyncresolver.resolve",
            new=AsyncMock(return_value=_a_answer("9.9.9.9")),
        ):
            r = await v.verify("acme.com")
        assert r.verified is False
        assert "1.2.3.4" in r.reason
        assert "9.9.9.9" in r.reason

    @pytest.mark.asyncio
    async def test_nxdomain(self):
        v = ARecordVerifier(["1.2.3.4"])
        with patch(
            "services.verifiers.a_record_verifier.dns.asyncresolver.resolve",
            new=AsyncMock(side_effect=dns.resolver.NXDOMAIN()),
        ):
            r = await v.verify("missing.com")
        assert r.verified is False
        assert "NXDOMAIN" in r.reason

    @pytest.mark.asyncio
    async def test_no_answer(self):
        v = ARecordVerifier(["1.2.3.4"])
        with patch(
            "services.verifiers.a_record_verifier.dns.asyncresolver.resolve",
            new=AsyncMock(side_effect=dns.resolver.NoAnswer()),
        ):
            r = await v.verify("acme.com")
        assert r.verified is False
        assert "1.2.3.4" in r.reason

    @pytest.mark.asyncio
    async def test_timeout_returns_failure(self):
        v = ARecordVerifier(["1.2.3.4"])
        with patch(
            "services.verifiers.a_record_verifier.dns.asyncresolver.resolve",
            new=AsyncMock(side_effect=asyncio.TimeoutError()),
        ):
            r = await v.verify("slow.com")
        assert r.verified is False
        assert "timed out" in r.reason

    @pytest.mark.asyncio
    async def test_generic_dns_exception_swallowed(self):
        # Verifiers MUST NOT raise on DNS errors — every DNSException
        # subclass must become a VerificationResult(verified=False).
        v = ARecordVerifier(["1.2.3.4"])

        class WeirdDnsError(dns.exception.DNSException):
            pass

        with patch(
            "services.verifiers.a_record_verifier.dns.asyncresolver.resolve",
            new=AsyncMock(side_effect=WeirdDnsError("upstream broke")),
        ):
            r = await v.verify("acme.com")
        assert r.verified is False
        assert "DNS error" in r.reason
