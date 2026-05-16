"""Resolve Host header → TenantInfo on every request.

Lands `request.state.tenant` for downstream handlers. Redirect route
reads it to scope the URL lookup to the right tenant. Unknown public
hosts get a 404; internal/loopback hosts (healthcheck, container exec)
pass through with tenant=None so /health doesn't break.
"""

from __future__ import annotations

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

from infrastructure.logging import get_logger
from services.tenant_resolver.protocol import TenantInfo, TenantResolver

log = get_logger(__name__)

_LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1", "app"})


def _split_host(raw: str) -> str:
    return raw.split(":", 1)[0].strip().lower()


class TenantMiddleware(BaseHTTPMiddleware):
    """Populates request.state.tenant from the request Host header."""

    async def dispatch(self, request: Request, call_next) -> Response:
        resolver: TenantResolver | None = getattr(
            request.app.state, "tenant_resolver", None
        )
        if resolver is None:
            return await call_next(request)

        host = _split_host(request.headers.get("host", ""))
        if not host or host in _LOOPBACK_HOSTS:
            request.state.tenant = None
            return await call_next(request)

        tenant: TenantInfo | None = await resolver.resolve(host)
        request.state.tenant = tenant
        if tenant is None:
            log.info("tenant_unknown_host", host=host)
            return JSONResponse({"error": "unknown_host"}, status_code=404)
        return await call_next(request)
