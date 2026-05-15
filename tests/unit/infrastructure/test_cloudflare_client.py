"""Unit tests for CloudflareClient."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

from errors import CloudflareAPIError, CloudflareNotConfiguredError
from infrastructure.cloudflare_client import (
    CF_API_BASE,
    CFHostnameResult,
    CloudflareClient,
)


def _http_client_with_response(
    payload: dict,
    *,
    status_code: int = 200,
    headers: dict[str, str] | None = None,
) -> tuple[MagicMock, AsyncMock]:
    response = MagicMock(spec=httpx.Response)
    response.status_code = status_code
    response.is_success = 200 <= status_code < 300
    response.json.return_value = payload
    response.text = "body"
    response.headers = headers or {}
    http = MagicMock()
    http.request = AsyncMock(return_value=response)
    return http, http.request


def _hostname_payload(**overrides) -> dict:
    base = {
        "id": "abc123",
        "hostname": "links.acme.com",
        "status": "pending",
        "ssl": {
            "status": "pending_validation",
            "validation_errors": [],
            "validation_records": [],
        },
    }
    base.update(overrides)
    return base


class TestCloudflareClient:
    async def test_create_custom_hostname_posts_correct_payload(self):
        http, request = _http_client_with_response({"result": _hostname_payload()})
        client = CloudflareClient(
            http_client=http,
            api_token="tok",
            zone_id="zone1",
        )

        result = await client.create_custom_hostname("links.acme.com", dcv_method="txt")

        assert isinstance(result, CFHostnameResult)
        assert result.id == "abc123"
        assert result.status == "pending"
        request.assert_awaited_once()
        kwargs = request.await_args.kwargs
        assert kwargs["json"] == {
            "hostname": "links.acme.com",
            "ssl": {
                "method": "txt",
                "type": "dv",
                "settings": {"min_tls_version": "1.2"},
            },
        }
        assert kwargs["headers"]["Authorization"] == "Bearer tok"
        assert request.await_args.args == (
            "POST",
            f"{CF_API_BASE}/zones/zone1/custom_hostnames",
        )

    async def test_get_custom_hostname_returns_parsed_result(self):
        http, _ = _http_client_with_response(
            {"result": _hostname_payload(status="active", ssl={"status": "active"})}
        )
        client = CloudflareClient(http_client=http, api_token="t", zone_id="z")
        result = await client.get_custom_hostname("abc123")
        assert result.status == "active"
        assert result.ssl_status == "active"

    async def test_delete_returns_true_on_404(self):
        response = MagicMock(spec=httpx.Response)
        response.status_code = 404
        response.is_success = False
        response.text = "not found"
        response.headers = {}
        http = MagicMock()
        http.request = AsyncMock(return_value=response)
        client = CloudflareClient(http_client=http, api_token="t", zone_id="z")

        ok = await client.delete_custom_hostname("abc123")
        assert ok is True

    async def test_4xx_raises_immediately_no_retry(self):
        response = MagicMock(spec=httpx.Response)
        response.status_code = 400
        response.is_success = False
        response.text = "bad request"
        response.headers = {}
        http = MagicMock()
        http.request = AsyncMock(return_value=response)
        client = CloudflareClient(
            http_client=http, api_token="t", zone_id="z", max_retries=3
        )

        with pytest.raises(CloudflareAPIError):
            await client.get_custom_hostname("abc")
        assert http.request.await_count == 1  # no retry on 4xx

    async def test_5xx_retries_then_raises(self, mocker):
        response = MagicMock(spec=httpx.Response)
        response.status_code = 503
        response.is_success = False
        response.text = "down"
        response.headers = {}
        http = MagicMock()
        http.request = AsyncMock(return_value=response)
        # Skip the real sleep so the test stays fast.
        mocker.patch(
            "infrastructure.cloudflare_client.asyncio.sleep",
            new_callable=AsyncMock,
        )
        client = CloudflareClient(
            http_client=http,
            api_token="t",
            zone_id="z",
            max_retries=3,
            initial_backoff_seconds=0.01,
        )
        with pytest.raises(CloudflareAPIError):
            await client.get_custom_hostname("abc")
        assert http.request.await_count == 3

    async def test_network_error_retries_then_raises(self, mocker):
        http = MagicMock()
        http.request = AsyncMock(side_effect=httpx.ConnectError("boom"))
        mocker.patch(
            "infrastructure.cloudflare_client.asyncio.sleep",
            new_callable=AsyncMock,
        )
        client = CloudflareClient(
            http_client=http, api_token="t", zone_id="z", max_retries=2
        )
        with pytest.raises(CloudflareAPIError):
            await client.get_custom_hostname("abc")
        assert http.request.await_count == 2

    async def test_not_configured_raises(self):
        http = MagicMock()
        client = CloudflareClient(http_client=http, api_token=None, zone_id=None)
        with pytest.raises(CloudflareNotConfiguredError):
            await client.get_custom_hostname("abc")

    async def test_find_hostname_by_fqdn_returns_first_match(self):
        http, request = _http_client_with_response(
            {"result": [_hostname_payload(hostname="links.acme.com")]}
        )
        client = CloudflareClient(http_client=http, api_token="t", zone_id="z")
        found = await client.find_hostname_by_fqdn("links.acme.com")
        assert found is not None
        assert found.hostname == "links.acme.com"
        kwargs = request.await_args.kwargs
        assert kwargs["params"] == {"hostname": "links.acme.com"}

    async def test_find_hostname_returns_none_on_empty_results(self):
        http, _ = _http_client_with_response({"result": []})
        client = CloudflareClient(http_client=http, api_token="t", zone_id="z")
        assert await client.find_hostname_by_fqdn("missing.example") is None

    async def test_429_retries_with_retry_after(self, mocker):
        response = MagicMock(spec=httpx.Response)
        response.status_code = 429
        response.is_success = False
        response.text = "rate limited"
        response.headers = {"Retry-After": "0"}
        http = MagicMock()
        http.request = AsyncMock(return_value=response)
        sleep = mocker.patch(
            "infrastructure.cloudflare_client.asyncio.sleep",
            new_callable=AsyncMock,
        )
        client = CloudflareClient(
            http_client=http,
            api_token="t",
            zone_id="z",
            max_retries=3,
            initial_backoff_seconds=10.0,  # would dominate if Retry-After ignored
        )
        with pytest.raises(CloudflareAPIError):
            await client.get_custom_hostname("abc")
        assert http.request.await_count == 3
        # Retry-After honoured (0s) instead of exponential 10/20.
        for call in sleep.await_args_list:
            assert call.args[0] == 0.0

    async def test_429_falls_back_to_backoff_when_header_missing(self, mocker):
        response = MagicMock(spec=httpx.Response)
        response.status_code = 429
        response.is_success = False
        response.text = "rate limited"
        response.headers = {}
        http = MagicMock()
        http.request = AsyncMock(return_value=response)
        sleep = mocker.patch(
            "infrastructure.cloudflare_client.asyncio.sleep",
            new_callable=AsyncMock,
        )
        client = CloudflareClient(
            http_client=http,
            api_token="t",
            zone_id="z",
            max_retries=2,
            initial_backoff_seconds=0.5,
        )
        with pytest.raises(CloudflareAPIError):
            await client.get_custom_hostname("abc")
        # First sleep used the exponential backoff (0.5 * 2^0 = 0.5).
        sleep.assert_awaited_with(0.5)
