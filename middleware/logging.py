"""
Request logging middleware — generates request_id, logs request/response metadata.

Uses structlog contextvars for propagation so service/repo layers can access
request_id without explicit parameter passing.
"""

from __future__ import annotations

import time
import uuid

import structlog
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

from infrastructure.logging import get_logger, hash_ip
from shared.ip_utils import get_client_ip

log = get_logger("spoo.request")

# Paths to skip detailed logging (high-volume, low-value)
_SKIP_PATHS = frozenset({"/health", "/favicon.ico"})


# Auth header inference — gives a coarse "who is calling" tag without leaking creds.
def _auth_kind(request: Request) -> str:
    auth = request.headers.get("authorization", "")
    if auth.startswith("Bearer "):
        token = auth[7:]
        if token.startswith("spoo_"):
            return "api_key"
        if token.count(".") == 2:
            return "jwt"
        return "bearer_other"
    if request.cookies.get("session"):
        return "session_cookie"
    return "anonymous"


def _generate_request_id() -> str:
    return f"req_{uuid.uuid4().hex[:12]}"


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        request_id = _generate_request_id()
        start = time.perf_counter()
        path = request.url.path

        ua = request.headers.get("user-agent", "")
        country = request.headers.get("cf-ipcountry")
        referrer = request.headers.get("referer")
        ip_hash = hash_ip(get_client_ip(request))
        auth_kind = _auth_kind(request)

        # Bind rich request context to structlog contextvars — every downstream
        # log call (services, repositories, etc.) inherits these fields.
        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(
            request_id=request_id,
            http_method=request.method,
            http_path=path,
            ip_hash=ip_hash,
            country=country,
            referrer=referrer,
            user_agent=ua[:200] if ua else None,
            auth_kind=auth_kind,
        )

        response = await call_next(request)

        duration_ms = int((time.perf_counter() - start) * 1000)
        response.headers["X-Request-ID"] = request_id

        if path not in _SKIP_PATHS:
            status = response.status_code
            log_fn = (
                log.error
                if status >= 500
                else (log.warning if status >= 400 else log.info)
            )
            log_fn(
                "request_completed",
                query=request.url.query or None,
                status_code=status,
                duration_ms=duration_ms,
                content_length=response.headers.get("content-length"),
                content_type=response.headers.get("content-type"),
                cache_status=response.headers.get("cf-cache-status"),
                slow=duration_ms > 500,
            )

        return response
