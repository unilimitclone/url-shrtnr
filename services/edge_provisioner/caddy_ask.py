"""CaddyAskProvisioner — talks to Caddy's admin API to evict revoked hosts."""

from __future__ import annotations

import httpx

from infrastructure.http_client import HttpClient
from infrastructure.logging import get_logger
from services.edge_provisioner.protocol import EdgeProvisioner

log = get_logger(__name__)


class CaddyAskProvisioner(EdgeProvisioner):
    def __init__(self, http_client: HttpClient, caddy_admin_url: str) -> None:
        self._http = http_client
        # Strip trailing slash so URL building stays predictable.
        self._admin_url = caddy_admin_url.rstrip("/")

    async def announce_revoked(self, fqdn: str) -> None:
        # POST to /id/<fqdn> against the Caddy admin API. The exact endpoint
        # semantics (delete vs update) are wired in PR3 alongside the
        # Caddyfile changes; here we just emit the announcement and swallow
        # all failures — the ask endpoint defaulting to deny is the
        # authoritative kill switch.
        url = f"{self._admin_url}/id/{fqdn}"
        try:
            response = await self._http.post(url)
            log.info(
                "caddy_revocation_announced",
                fqdn=fqdn,
                status_code=response.status_code,
            )
        except httpx.HTTPError as exc:
            log.warning(
                "caddy_revocation_announce_failed",
                fqdn=fqdn,
                error=str(exc),
                error_type=type(exc).__name__,
            )
