"""Async Cloudflare Workers KV client — edge-cache namespace only.

Scope: PUT/DELETE of edge-cache entries in a single KV namespace.
Custom Hostnames live in :mod:`infrastructure.cloudflare_client`; that
client's docstring scopes it deliberately, and the same rule applies
here in reverse. Transport (auth, retry, backoff) is shared via
:class:`CloudflareSession`.

Unlike ``CloudflareClient`` (which raises so wiring bugs surface), every
method here returns a bool: both call sites — the hot-URL promotion
action and future invalidation — are best-effort by contract, and a
raising client would just force try/except at each one. A failed PUT
means one URL isn't edge-served this window; a failed DELETE is bounded
by the KV entry's TTL. Both are logged, never fatal.
"""

from __future__ import annotations

from urllib.parse import quote

import httpx

from infrastructure.cloudflare_client import CF_API_BASE
from infrastructure.cloudflare_session import CloudflareSession
from infrastructure.http_client import HttpClient
from infrastructure.logging import get_logger

log = get_logger(__name__)


class CloudflareKVClient:
    """Minimal Workers KV writer.

    The KV REST API is account-scoped:
    ``/accounts/{account_id}/storage/kv/namespaces/{namespace_id}/values/{key}``.
    ``api_base`` overrides the account-scoped root for local development —
    wrangler dev's Explorer API mirrors the same ``/storage/kv/...`` paths
    (``http://localhost:8787/cdn-cgi/explorer/api``).
    """

    def __init__(
        self,
        *,
        http_client: HttpClient,
        api_token: str | None,
        account_id: str | None,
        namespace_id: str | None,
        api_base: str | None = None,
        api_host_header: str | None = None,
        max_retries: int = 3,
        initial_backoff_seconds: float = 1.0,
    ) -> None:
        self._account_id = account_id
        self._namespace_id = namespace_id
        self._api_base = api_base
        self._token = api_token
        # base_url is meaningless while unconfigured; _request gates on
        # is_configured before the session is ever used.
        base_url = api_base or f"{CF_API_BASE}/accounts/{account_id}"
        self._session = CloudflareSession(
            http_client=http_client,
            api_token=api_token,
            base_url=base_url,
            host_header=api_host_header,
            max_retries=max_retries,
            initial_backoff_seconds=initial_backoff_seconds,
        )

    @property
    def is_configured(self) -> bool:
        return bool(
            self._token and self._namespace_id and (self._account_id or self._api_base)
        )

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

        # Keys ride in the URL path and can contain emoji (emoji short
        # codes) and reserved characters — CF requires them URL-encoded.
        # Encoding is transport-only: CF decodes before storing, so the
        # Worker's binding lookups see the raw key.
        path = (
            f"/storage/kv/namespaces/{self._namespace_id}/values/{quote(key, safe='')}"
        )
        try:
            response = await self._session.request(
                method, path, content=content, params=params
            )
        except httpx.HTTPError as exc:
            log.error(
                "cf_kv_retries_exhausted",
                method=method,
                key=key,
                error=str(exc),
            )
            return False

        if response.is_success or response.status_code in ok_statuses:
            return True

        if response.status_code >= 500 or response.status_code == 429:
            # Session already retried and logged each attempt.
            log.error("cf_kv_retries_exhausted", method=method, key=key)
            return False

        # Other 4xx: config/auth problem, retry can't help — surface
        # loudly in logs and give up.
        log.error(
            "cf_kv_request_rejected",
            method=method,
            key=key,
            cf_status_code=response.status_code,
            cf_body_preview=response.text[:300],
        )
        return False
