"""Unit tests for TenantMiddleware."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from middleware.tenant import TenantMiddleware
from schemas.enums.domain_status import DomainStatus
from services.tenant_resolver.protocol import TenantInfo


def _app(resolver=None, omit_resolver: bool = False) -> Starlette:
    async def root(request):
        tenant = getattr(request.state, "tenant", "<unset>")
        if tenant is None:
            return PlainTextResponse("none")
        if tenant == "<unset>":
            return PlainTextResponse("unset")
        return PlainTextResponse(tenant.fqdn)

    app = Starlette(routes=[Route("/", root)])
    if not omit_resolver:
        app.state.tenant_resolver = resolver
    app.add_middleware(TenantMiddleware)
    return app


class TestTenantMiddleware:
    def test_no_tenant_resolver_bypasses_middleware(self):
        # No resolver wired → middleware skips entirely, request.state.tenant
        # is never set. Guards against future code assuming the attribute exists.
        with TestClient(_app(omit_resolver=True)) as client:
            r = client.get("/", headers={"host": "example.com"})
        assert r.status_code == 200
        assert r.text == "unset"

    def test_unknown_host_returns_html_404(self):
        resolver = MagicMock()
        resolver.resolve = AsyncMock(return_value=None)
        with TestClient(_app(resolver)) as client:
            r = client.get("/", headers={"host": "bogus.example.com"})
        assert r.status_code == 404
        assert "text/html" in r.headers.get("content-type", "")
        assert "URL not found" in r.text

    def test_known_tenant_lands_on_request_state(self):
        resolver = MagicMock()
        resolver.resolve = AsyncMock(
            return_value=TenantInfo(
                domain_id=None,
                fqdn="links.acme.com",
                owner_id=None,
                status=DomainStatus.ACTIVE,
                is_system_default=False,
            )
        )
        with TestClient(_app(resolver)) as client:
            r = client.get("/", headers={"host": "links.acme.com"})
        assert r.status_code == 200
        assert r.text == "links.acme.com"

    def test_loopback_host_bypasses_resolver(self):
        resolver = MagicMock()
        resolver.resolve = AsyncMock(side_effect=AssertionError("should not be called"))
        with TestClient(_app(resolver)) as client:
            r = client.get("/", headers={"host": "localhost"})
        assert r.status_code == 200
        assert r.text == "none"

    def test_strips_port_before_resolving(self):
        resolver = MagicMock()
        captured: dict[str, str] = {}

        async def _capture(h):
            captured["host"] = h
            return TenantInfo(
                domain_id=None,
                fqdn=h,
                owner_id=None,
                status=DomainStatus.ACTIVE,
                is_system_default=False,
            )

        resolver.resolve = _capture
        with TestClient(_app(resolver)) as client:
            client.get("/", headers={"host": "links.acme.com:8443"})
        assert captured["host"] == "links.acme.com"

    def test_ipv6_bracketed_host_is_normalised(self):
        # `[::1]:8000` must become `::1`, not `[::1]`.
        resolver = MagicMock()
        resolver.resolve = AsyncMock(side_effect=AssertionError("should not be called"))
        with TestClient(_app(resolver)) as client:
            r = client.get("/", headers={"host": "[::1]:8000"})
        # `::1` is in the loopback set, so resolver should be skipped.
        assert r.status_code == 200
        assert r.text == "none"
