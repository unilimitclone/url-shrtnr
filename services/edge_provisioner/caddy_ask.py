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

    async def announce_revoked(self, fqdn: str) -> bool:
        # POST to /id/<fqdn> against the Caddy admin API. The exact endpoint
        # semantics (delete vs update) are wired in PR3 alongside the
        # Caddyfile changes. Three distinct log events so Axiom alerts can
        # fire on real failures without being polluted by 2xx noise:
        #   - caddy_revocation_announced  → 2xx, eviction succeeded
        #   - caddy_revocation_rejected   → upstream returned non-2xx
        #   - caddy_revocation_announce_failed → couldn't reach Caddy at all
        url = f"{self._admin_url}/id/{fqdn}"
        try:
            response = await self._http.post(url)
        except httpx.HTTPError as exc:
            log.warning(
                "caddy_revocation_announce_failed",
                fqdn=fqdn,
                error=str(exc),
                error_type=type(exc).__name__,
            )
            return False
        except Exception as exc:
            # Protocol contract: must not raise. Catch non-httpx escapees
            # (closed loop, OSError, etc.) so revoke() can finish cleanly.
            log.exception(
                "caddy_revocation_announce_unexpected_error",
                fqdn=fqdn,
                error=str(exc),
                error_type=type(exc).__name__,
            )
            return False

        if response.is_success:
            log.info(
                "caddy_revocation_announced",
                fqdn=fqdn,
                status_code=response.status_code,
            )
            return True

        log.warning(
            "caddy_revocation_rejected",
            fqdn=fqdn,
            status_code=response.status_code,
            # Truncate the body — Caddy errors are short text; cap at 500
            # chars so a misconfigured admin returning a giant response
            # can't blow up our log payload size.
            response_body=response.text[:500],
        )
        return False
