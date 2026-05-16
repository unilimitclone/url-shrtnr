"""Resolve Host header → TenantInfo on every request.

Lands `request.state.tenant` for downstream handlers. Redirect route
reads it to scope the URL lookup to the right tenant. Unknown public
hosts get an HTML 404; internal/loopback hosts pass through with
tenant=None so /health doesn't break.
"""

from __future__ import annotations

from urllib.parse import urlsplit

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import HTMLResponse, Response

from infrastructure.logging import get_logger
from services.tenant_resolver.protocol import TenantInfo, TenantResolver

log = get_logger(__name__)

_LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1", "app"})


def _normalise_host(raw: str) -> str:
    """Lowercased, dot-stripped, port-stripped host. RFC 3986-safe for
    bracketed IPv6 literals (urlsplit handles `[::1]:8000` correctly)."""
    if not raw:
        return ""
    try:
        parsed = urlsplit(f"//{raw.strip()}").hostname
    except ValueError:
        return ""
    return (parsed or "").rstrip(".").lower()


class TenantMiddleware(BaseHTTPMiddleware):
    """Populates request.state.tenant from the request Host header."""

    async def dispatch(self, request: Request, call_next) -> Response:
        resolver: TenantResolver | None = getattr(
            request.app.state, "tenant_resolver", None
        )
        if resolver is None:
            return await call_next(request)

        host = _normalise_host(request.headers.get("host", ""))
        if not host or host in _LOOPBACK_HOSTS:
            request.state.tenant = None
            return await call_next(request)

        tenant: TenantInfo | None = await resolver.resolve(host)
        request.state.tenant = tenant
        if tenant is None:
            log.info("tenant_unknown_host", host=host)
            # Static HTML 404 — browser-friendly, no template deps, no
            # tenancy details leaked.
            return HTMLResponse(_NOT_FOUND_BODY, status_code=404)
        return await call_next(request)


_NOT_FOUND_BODY = (
    "<!doctype html><html><head><title>404 — Not Found</title></head>"
    "<body><h1>404</h1><p>URL not found.</p></body></html>"
)
