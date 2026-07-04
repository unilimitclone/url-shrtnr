"""Async Cloudflare Workers KV client — edge-cache namespace only.

Scope: PUT/DELETE of edge-cache entries in a single KV namespace.
Custom Hostnames live in :mod:`infrastructure.cloudflare_client`; that
client's docstring scopes it deliberately, and the same rule applies
here in reverse.

Unlike ``CloudflareClient`` (which raises so wiring bugs surface), every
method here returns a bool: both call sites — the hot-URL promotion
action and the URL-cache invalidation mirror — are best-effort by
contract, and a raising client would just force try/except at each one.
A failed PUT means one URL isn't edge-served this window; a failed
DELETE is bounded by the KV entry's TTL. Both are logged, never fatal.
"""

from __future__ import annotations

import asyncio

import httpx

from infrastructure.cloudflare_client import CF_API_BASE
from infrastructure.http_client import HttpClient
from infrastructure.logging import get_logger

log = get_logger(__name__)


class CloudflareKVClient:
    """Minimal Workers KV writer with retry on 5xx/429.

    The KV REST API is account-scoped:
    ``/accounts/{account_id}/storage/kv/namespaces/{namespace_id}/values/{key}``.
    """

    def __init__(
        self,
        *,
        http_client: HttpClient,
        api_token: str | None,
        account_id: str | None,
        namespace_id: str | None,
        max_retries: int = 3,
        initial_backoff_seconds: float = 1.0,
    ) -> None:
        self._http = http_client
        self._token = api_token
        self._account_id = account_id
        self._namespace_id = namespace_id
        self._max_retries = max_retries
        self._initial_backoff = initial_backoff_seconds

    @property
    def is_configured(self) -> bool:
        return bool(self._token and self._account_id and self._namespace_id)

    async def put(self, key: str, value: str, *, expiration_ttl: int) -> bool:
        """Write *value* under *key*, auto-expiring after *expiration_ttl* s."""
        return await self._request(
            "PUT",
            key,
            content=value,
            params={"expiration_ttl": expiration_ttl},
        )

    async def delete(self, key: str) -> bool:
        """Idempotent delete — a 404 (already gone) counts as success."""
        return await self._request("DELETE", key, ok_statuses=(404,))

    async def _request(
        self,
        method: str,
        key: str,
        *,
        content: str | None = None,
        params: dict[str, int] | None = None,
        ok_statuses: tuple[int, ...] = (),
    ) -> bool:
        if not self.is_configured:
            log.warning("cf_kv_not_configured", method=method)
            return False

        url = (
            f"{CF_API_BASE}/accounts/{self._account_id}"
            f"/storage/kv/namespaces/{self._namespace_id}/values/{key}"
        )
        headers = {"Authorization": f"Bearer {self._token}"}

        for attempt in range(self._max_retries):
            try:
                response = await self._http.request(
                    method, url, headers=headers, content=content, params=params
                )
            except httpx.HTTPError as exc:
                log.warning(
                    "cf_kv_transport_error",
                    method=method,
                    key=key,
                    error=str(exc),
                    attempt=attempt,
                )
                await self._sleep_backoff(attempt)
                continue

            if response.is_success or response.status_code in ok_statuses:
                return True

            if response.status_code >= 500 or response.status_code == 429:
                log.warning(
                    "cf_kv_retryable_error",
                    method=method,
                    key=key,
                    cf_status_code=response.status_code,
                    attempt=attempt,
                )
                await self._sleep_backoff(attempt)
                continue

            # 4xx other than 404-on-delete: config/auth problem, retry
            # can't help — surface loudly in logs and give up.
            log.error(
                "cf_kv_request_rejected",
                method=method,
                key=key,
                cf_status_code=response.status_code,
                cf_body_preview=response.text[:300],
            )
            return False

        log.error("cf_kv_retries_exhausted", method=method, key=key)
        return False

    async def _sleep_backoff(self, attempt: int) -> None:
        if attempt + 1 < self._max_retries:
            await asyncio.sleep(self._initial_backoff * (2**attempt))
