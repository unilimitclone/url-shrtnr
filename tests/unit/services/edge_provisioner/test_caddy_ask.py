"""Unit tests for CaddyAskProvisioner.announce_revoked()."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from services.edge_provisioner.caddy_ask import CaddyAskProvisioner


def _http_client(response: MagicMock | None = None, exc: Exception | None = None):
    client = MagicMock()
    if exc is not None:
        client.post = AsyncMock(side_effect=exc)
    else:
        client.post = AsyncMock(return_value=response)
    return client


def _response(status_code: int, text: str = "") -> MagicMock:
    r = MagicMock(spec=httpx.Response)
    r.status_code = status_code
    r.is_success = 200 <= status_code < 300
    r.text = text
    return r


class TestAnnounceRevoked:
    @pytest.mark.asyncio
    async def test_returns_true_on_2xx(self):
        http = _http_client(_response(200))
        p = CaddyAskProvisioner(http, "http://caddy:2019")
        with patch("services.edge_provisioner.caddy_ask.log") as log:
            ok = await p.announce_revoked("links.acme.com")
        assert ok is True
        log.info.assert_called_once()
        assert log.info.call_args.args[0] == "caddy_revocation_announced"
        log.warning.assert_not_called()

    @pytest.mark.asyncio
    async def test_strips_admin_url_trailing_slash(self):
        http = _http_client(_response(204))
        p = CaddyAskProvisioner(http, "http://caddy:2019/")
        await p.announce_revoked("links.acme.com")
        called_url = http.post.call_args.args[0]
        # No double slash between admin URL and /id/...
        assert called_url == "http://caddy:2019/id/links.acme.com"

    @pytest.mark.asyncio
    async def test_returns_false_on_4xx(self):
        http = _http_client(_response(404, text="not found"))
        p = CaddyAskProvisioner(http, "http://caddy:2019")
        with patch("services.edge_provisioner.caddy_ask.log") as log:
            ok = await p.announce_revoked("links.acme.com")
        assert ok is False
        # Distinct event name so Axiom can alert without false positives
        # from the success path.
        log.warning.assert_called_once()
        assert log.warning.call_args.args[0] == "caddy_revocation_rejected"
        log.info.assert_not_called()

    @pytest.mark.asyncio
    async def test_returns_false_on_5xx(self):
        http = _http_client(_response(500))
        p = CaddyAskProvisioner(http, "http://caddy:2019")
        ok = await p.announce_revoked("links.acme.com")
        assert ok is False

    @pytest.mark.asyncio
    async def test_returns_false_on_transport_error(self):
        http = _http_client(exc=httpx.ConnectError("boom"))
        p = CaddyAskProvisioner(http, "http://caddy:2019")
        with patch("services.edge_provisioner.caddy_ask.log") as log:
            ok = await p.announce_revoked("links.acme.com")
        assert ok is False
        log.warning.assert_called_once()
        assert log.warning.call_args.args[0] == "caddy_revocation_announce_failed"

    @pytest.mark.asyncio
    async def test_truncates_large_response_body(self):
        # Misconfigured Caddy admin returning a huge body shouldn't blow
        # up our log payload size — cap at 500 chars.
        http = _http_client(_response(500, text="x" * 10_000))
        p = CaddyAskProvisioner(http, "http://caddy:2019")
        with patch("services.edge_provisioner.caddy_ask.log") as log:
            await p.announce_revoked("links.acme.com")
        body = log.warning.call_args.kwargs["response_body"]
        assert len(body) == 500
