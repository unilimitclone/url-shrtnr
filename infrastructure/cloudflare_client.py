"""Async Cloudflare API client — Custom Hostnames endpoints only.

Scope: SaaS Custom Hostnames CRUD (create/get/delete) for the spoo.me zone.
Anything broader belongs in a separate client. Bearer-token auth, tolerant
of missing config so self-hosters who skip CF entirely don't crash on
import.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any

import httpx

from errors import CloudflareAPIError, CloudflareNotConfiguredError
from infrastructure.http_client import HttpClient
from infrastructure.logging import get_logger

log = get_logger(__name__)

CF_API_BASE = "https://api.cloudflare.com/client/v4"


@dataclass(frozen=True)
class CFHostnameResult:
    """Subset of CF Custom Hostname payload the service layer cares about."""

    id: str
    hostname: str
    status: str  # "pending" | "active" | "moved" | "deleted" | "blocked"
    ssl_status: str  # "initializing" | "pending_validation" | "active" | ...
    verification_errors: list[str] = field(default_factory=list)
    # DCV records the customer needs to add. Shape depends on dcv_method:
    # - delegated: empty (handled via permanent CNAME)
    # - http: [{name: "<token>", value: "<expected>", type: "http"}]
    # - txt:  [{name: "_acme-challenge.<host>", value: "<token>", type: "txt"}]
    verification_records: list[dict[str, Any]] = field(default_factory=list)


class CloudflareClient:
    """Minimal CF Custom Hostnames client with retry on 5xx.

    All methods raise ``CloudflareNotConfiguredError`` when the bearer token
    or zone id is missing — wiring should never construct this client without
    them, so a raise here surfaces a wiring bug, not a customer-visible error.
    """

    def __init__(
        self,
        *,
        http_client: HttpClient,
        api_token: str | None,
        zone_id: str | None,
        max_retries: int = 3,
        initial_backoff_seconds: float = 1.0,
    ) -> None:
        self._http = http_client
        self._token = api_token
        self._zone_id = zone_id
        self._max_retries = max_retries
        self._initial_backoff = initial_backoff_seconds

    @property
    def is_configured(self) -> bool:
        return bool(self._token and self._zone_id)

    async def create_custom_hostname(
        self,
        fqdn: str,
        *,
        dcv_method: str,
    ) -> CFHostnameResult:
        """Register *fqdn* with CF SaaS.

        ``dcv_method`` is one of ``"txt"`` (delegated), ``"http"``, ``"email"``.
        Spoo uses ``"txt"`` for delegated DCV (CF auto-renews via the
        permanent ``_acme-challenge`` CNAME) and ``"http"`` as fallback.
        """
        body = {
            "hostname": fqdn,
            "ssl": {
                "method": dcv_method,
                "type": "dv",
                "settings": {"min_tls_version": "1.2"},
            },
        }
        payload = await self._request(
            "POST",
            f"/zones/{self._zone_id}/custom_hostnames",
            json=body,
        )
        return _parse_hostname(payload["result"])

    async def get_custom_hostname(self, hostname_id: str) -> CFHostnameResult:
        payload = await self._request(
            "GET",
            f"/zones/{self._zone_id}/custom_hostnames/{hostname_id}",
        )
        return _parse_hostname(payload["result"])

    async def delete_custom_hostname(self, hostname_id: str) -> bool:
        """Idempotent — 404 returns True (already gone)."""
        try:
            await self._request(
                "DELETE",
                f"/zones/{self._zone_id}/custom_hostnames/{hostname_id}",
            )
        except CloudflareAPIError as exc:
            if exc.details and exc.details.get("status_code") == 404:
                return True
            raise
        return True

    async def find_hostname_by_fqdn(self, fqdn: str) -> CFHostnameResult | None:
        """Recovery path when a doc lost its ``cf_hostname_id``."""
        payload = await self._request(
            "GET",
            f"/zones/{self._zone_id}/custom_hostnames",
            params={"hostname": fqdn},
        )
        results = payload.get("result") or []
        if not results:
            return None
        return _parse_hostname(results[0])

    async def _request(
        self,
        method: str,
        path: str,
        *,
        json: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        if not self.is_configured:
            raise CloudflareNotConfiguredError(
                "CloudflareClient invoked without api_token + zone_id."
            )

        url = f"{CF_API_BASE}{path}"
        headers = {
            "Authorization": f"Bearer {self._token}",
            "Content-Type": "application/json",
        }

        last_exc: Exception | None = None
        for attempt in range(self._max_retries):
            try:
                response = await self._http.request(
                    method, url, headers=headers, json=json, params=params
                )
            except httpx.HTTPError as exc:
                last_exc = exc
                await self._sleep_backoff(attempt)
                continue

            # Retry on 5xx and 429. 429 honours Retry-After when present
            # so we don't hammer past CF's window (1200 req/5min/zone).
            if response.status_code >= 500 or response.status_code == 429:
                last_exc = CloudflareAPIError(
                    f"CF API {method} {path} returned {response.status_code}",
                    details={
                        "status_code": response.status_code,
                        "body": response.text[:500],
                    },
                )
                retry_after = _parse_retry_after(response)
                await self._sleep_backoff(attempt, override_seconds=retry_after)
                continue

            if not response.is_success:
                raise CloudflareAPIError(
                    f"CF API {method} {path} returned {response.status_code}",
                    details={
                        "status_code": response.status_code,
                        "body": response.text[:500],
                    },
                )

            # CF v4 can return 2xx with `success: false` for validation
            # failures — must surface as our error type, not a downstream
            # KeyError on `result`.
            try:
                payload = response.json()
            except ValueError as exc:
                raise CloudflareAPIError(
                    f"CF API {method} {path} returned malformed JSON",
                    details={"status_code": response.status_code},
                ) from exc

            if isinstance(payload, dict) and payload.get("success") is False:
                raise CloudflareAPIError(
                    f"CF API {method} {path} reported success=false",
                    details={
                        "status_code": response.status_code,
                        "errors": payload.get("errors"),
                        "messages": payload.get("messages"),
                    },
                )

            return payload

        # All retries failed.
        if isinstance(last_exc, CloudflareAPIError):
            raise last_exc
        raise CloudflareAPIError(
            f"CF API {method} {path} failed after {self._max_retries} attempts",
            details={"underlying_error": str(last_exc)},
        ) from last_exc

    async def _sleep_backoff(
        self, attempt: int, *, override_seconds: float | None = None
    ) -> None:
        # Last attempt — let caller raise instead of sleeping pointlessly.
        if attempt >= self._max_retries - 1:
            return
        delay = (
            override_seconds
            if override_seconds is not None
            else self._initial_backoff * (2**attempt)
        )
        await asyncio.sleep(delay)


def _parse_retry_after(response: httpx.Response) -> float | None:
    """Honour CF's Retry-After header (seconds form). Drop malformed input
    silently — fall back to exponential backoff."""
    raw = response.headers.get("Retry-After")
    if not raw:
        return None
    try:
        return max(0.0, float(raw))
    except ValueError:
        return None


def _parse_hostname(raw: dict[str, Any]) -> CFHostnameResult:
    ssl = raw.get("ssl") or {}
    return CFHostnameResult(
        id=raw["id"],
        hostname=raw["hostname"],
        status=raw.get("status", "unknown"),
        ssl_status=ssl.get("status", "unknown"),
        verification_errors=list(ssl.get("validation_errors") or []),
        verification_records=list(ssl.get("validation_records") or []),
    )
