"""EdgeProvisioner protocol — abstracts the cert/edge-config plane.

Exists so the orchestrator can announce domain revocations without
coupling to Caddy's specific admin API. Future deployments could swap in
a Cloudflare-for-SaaS provisioner without touching service code.
"""

from __future__ import annotations

from typing import Protocol


class EdgeProvisioner(Protocol):
    async def announce_revoked(self, fqdn: str) -> None:
        """Notify the edge that *fqdn* is no longer authorised.

        Best-effort. The on-demand TLS ask endpoint flipping to deny is the
        real authority — this call just nudges the edge to evict any cached
        cert/config eagerly. Implementations MUST NOT raise on transport or
        upstream failures (the worst case is a brief window where the edge
        keeps serving a now-revoked cert until LE expiry; ack the cost).
        """
        ...
