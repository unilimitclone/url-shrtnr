"""Unit tests for the DNS preflight check + CF-DNS detector."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from services.dns_preflight import check_cname, uses_cloudflare_dns


async def _ok_one(fqdn, ns):
    return ["customers.spoo.me"]


async def _all_unknown(fqdn, ns):
    return []


async def _wrong_target(fqdn, ns):
    return ["someoneelse.example"]


async def _network_error(fqdn, ns):
    return None


class TestCheckCname:
    @pytest.mark.asyncio
    async def test_pass_when_one_resolver_sees_expected_target(self):
        with patch("services.dns_preflight._query_one", side_effect=_ok_one):
            result = await check_cname("links.acme.com", "customers.spoo.me")
        assert result.ok is True

    @pytest.mark.asyncio
    async def test_normalises_trailing_dots(self):
        with patch("services.dns_preflight._query_one", side_effect=_ok_one):
            result = await check_cname("links.acme.com.", "customers.spoo.me.")
        assert result.ok is True

    @pytest.mark.asyncio
    async def test_unknown_record_yields_friendly_propagation_message(self):
        with patch("services.dns_preflight._query_one", side_effect=_all_unknown):
            result = await check_cname("links.acme.com", "customers.spoo.me")
        assert result.ok is False
        assert "propagating" in result.reason

    @pytest.mark.asyncio
    async def test_wrong_target_yields_diagnostic_message(self):
        with patch("services.dns_preflight._query_one", side_effect=_wrong_target):
            result = await check_cname("links.acme.com", "customers.spoo.me")
        assert result.ok is False
        assert "someoneelse.example" in result.reason
        assert "customers.spoo.me" in result.reason

    @pytest.mark.asyncio
    async def test_transport_errors_treated_as_unpropagated(self):
        with patch("services.dns_preflight._query_one", side_effect=_network_error):
            result = await check_cname("links.acme.com", "customers.spoo.me")
        assert result.ok is False


class TestUsesCloudflareDns:
    @pytest.mark.asyncio
    async def test_detects_cf_ns_at_apex(self):
        class _RData:
            def __init__(self, target: str) -> None:
                self.target = target

        async def _fake_resolve(name, rrtype):
            assert rrtype == "NS"
            if name == "acme.com":
                return [_RData("kara.ns.cloudflare.com.")]
            raise __import__("dns.resolver", fromlist=["NoAnswer"]).NoAnswer()

        with patch(
            "dns.asyncresolver.Resolver.resolve",
            side_effect=_fake_resolve,
        ):
            assert await uses_cloudflare_dns("links.acme.com") is True

    @pytest.mark.asyncio
    async def test_returns_false_for_non_cf_ns(self):
        class _RData:
            def __init__(self, target: str) -> None:
                self.target = target

        async def _fake_resolve(name, rrtype):
            if name == "acme.com":
                return [_RData("ns1.somewhere-else.net.")]
            raise __import__("dns.resolver", fromlist=["NoAnswer"]).NoAnswer()

        with patch(
            "dns.asyncresolver.Resolver.resolve",
            side_effect=_fake_resolve,
        ):
            assert await uses_cloudflare_dns("links.acme.com") is False
