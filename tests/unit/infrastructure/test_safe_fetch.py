"""SSRF-guard tests for infrastructure/safe_fetch.py."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from infrastructure.safe_fetch import (
    FetchHardError,
    _is_public,
    _resolve_public_ip,
    fetch_public_image,
)

# ── _is_public matrix ─────────────────────────────────────────────────────────


class TestIsPublic:
    @pytest.mark.parametrize(
        "ip",
        [
            "10.0.0.1",
            "172.16.5.5",
            "192.168.1.1",
            "127.0.0.1",
            "169.254.169.254",  # cloud metadata
            "0.0.0.0",
            "::1",
            "fe80::1",
            "fd00::1",  # ULA
            "::ffff:10.0.0.1",  # IPv4-mapped bypass attempt
            "224.0.0.1",  # multicast
        ],
    )
    def test_private_and_special_rejected(self, ip):
        assert _is_public(ip) is False

    @pytest.mark.parametrize("ip", ["93.184.216.34", "2606:2800:220:1::1"])
    def test_public_accepted(self, ip):
        assert _is_public(ip) is True


# ── resolution guard ──────────────────────────────────────────────────────────


class TestResolvePublicIp:
    @pytest.mark.asyncio
    async def test_literal_private_ip_rejected(self):
        with pytest.raises(FetchHardError):
            await _resolve_public_ip("169.254.169.254")

    @pytest.mark.asyncio
    async def test_literal_public_ip_accepted(self):
        assert await _resolve_public_ip("93.184.216.34") == "93.184.216.34"

    @pytest.mark.asyncio
    async def test_mixed_record_set_rejected(self):
        # ANY private record fails the host — the rebinding/split-horizon shape.
        def _answer(host, rdtype):
            rec_public = AsyncMock()
            rec_public.to_text = lambda: "93.184.216.34"
            rec_private = AsyncMock()
            rec_private.to_text = lambda: "10.0.0.1"
            answer = AsyncMock()
            if rdtype == "A":
                answer.__iter__ = lambda self: iter([rec_public, rec_private])
            else:
                answer.__iter__ = lambda self: iter([])
            return answer

        with (
            patch(
                "infrastructure.safe_fetch.dns.asyncresolver.resolve",
                new=AsyncMock(side_effect=_answer),
            ),
            pytest.raises(FetchHardError, match="non-public"),
        ):
            await _resolve_public_ip("evil.example.com")


# ── fetch-level guards (no network: fail before connecting) ─────────────────


class TestFetchGuards:
    @pytest.mark.asyncio
    async def test_http_url_rejected(self):
        with pytest.raises(FetchHardError, match="non-https"):
            await fetch_public_image("http://example.com/a.png")

    @pytest.mark.asyncio
    async def test_private_host_rejected_before_any_connection(self):
        with pytest.raises(FetchHardError):
            await fetch_public_image("https://127.0.0.1/a.png")

    @pytest.mark.asyncio
    async def test_metadata_endpoint_rejected(self):
        with pytest.raises(FetchHardError):
            await fetch_public_image("https://169.254.169.254/latest/meta-data")
