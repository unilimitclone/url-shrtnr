"""Unit tests for TenantMiddleware (PR4: strict allowlist routing)."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route

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

    async def alias(request):
        tenant = getattr(request.state, "tenant", None)
        body = tenant.fqdn if tenant else "anon"
        return PlainTextResponse(body)

    app = Starlette(
        routes=[
            Route("/", root),
            Route("/{alias:str}", alias),
        ]
    )
    if not omit_resolver:
        app.state.tenant_resolver = resolver
    app.add_middleware(TenantMiddleware)
    return app


def _custom_tenant(fqdn: str = "links.acme.com") -> TenantInfo:
    return TenantInfo(
        domain_id=None,
        fqdn=fqdn,
        owner_id=None,
        status=DomainStatus.ACTIVE,
        is_system_default=False,
    )


def _system_tenant(fqdn: str = "spoo.me") -> TenantInfo:
    return TenantInfo(
        domain_id=None,
        fqdn=fqdn,
        owner_id=None,
        status=DomainStatus.ACTIVE,
        is_system_default=True,
    )


def _client(resolver):
    from starlette.testclient import TestClient

    return TestClient(_app(resolver))


class TestTenantMiddleware:
    def test_no_tenant_resolver_bypasses_middleware(self):
        from starlette.testclient import TestClient

        with TestClient(_app(omit_resolver=True)) as client:
            r = client.get("/", headers={"host": "example.com"})
        assert r.status_code == 200
        assert r.text == "unset"

    def test_unknown_host_returns_html_404(self):
        resolver = MagicMock()
        resolver.resolve = AsyncMock(return_value=None)
        with _client(resolver) as client:
            r = client.get("/", headers={"host": "bogus.example.com"})
        assert r.status_code == 404
        assert "text/html" in r.headers.get("content-type", "")
        assert "URL not found" in r.text

    def test_system_tenant_root_passes_through(self):
        resolver = MagicMock()
        resolver.resolve = AsyncMock(return_value=_system_tenant())
        with _client(resolver) as client:
            r = client.get("/", headers={"host": "spoo.me"})
        assert r.status_code == 200
        assert r.text == "spoo.me"
        # System default: no noindex stamp on responses (existing redirect
        # route handles its own header).
        assert "X-Robots-Tag" not in r.headers

    def test_system_tenant_alias_passes_through(self):
        resolver = MagicMock()
        resolver.resolve = AsyncMock(return_value=_system_tenant())
        with _client(resolver) as client:
            r = client.get("/abc", headers={"host": "spoo.me"})
        assert r.status_code == 200
        assert r.text == "spoo.me"

    def test_loopback_host_bypasses_resolver(self):
        resolver = MagicMock()
        resolver.resolve = AsyncMock(side_effect=AssertionError("should not be called"))
        with _client(resolver) as client:
            r = client.get("/", headers={"host": "localhost"})
        assert r.status_code == 200
        assert r.text == "none"

    def test_strips_port_before_resolving(self):
        resolver = MagicMock()
        captured: dict[str, str] = {}

        async def _capture(h):
            captured["host"] = h
            return _system_tenant(fqdn=h)

        resolver.resolve = _capture
        with _client(resolver) as client:
            client.get("/", headers={"host": "links.acme.com:8443"})
        assert captured["host"] == "links.acme.com"

    def test_ipv6_bracketed_host_is_normalised(self):
        resolver = MagicMock()
        resolver.resolve = AsyncMock(side_effect=AssertionError("should not be called"))
        with _client(resolver) as client:
            r = client.get("/", headers={"host": "[::1]:8000"})
        assert r.status_code == 200
        assert r.text == "none"


class TestCustomTenantRouting:
    """Allowlist routing on custom tenants — strict 404 on operator surface."""

    def test_custom_root_returns_404(self):
        resolver = MagicMock()
        resolver.resolve = AsyncMock(return_value=_custom_tenant())
        with _client(resolver) as client:
            r = client.get("/", headers={"host": "links.acme.com"})
        assert r.status_code == 404
        assert r.headers["X-Robots-Tag"] == "noindex, nofollow, noarchive"

    def test_custom_alias_passes_through(self):
        resolver = MagicMock()
        resolver.resolve = AsyncMock(return_value=_custom_tenant())
        with _client(resolver) as client:
            r = client.get("/abc123", headers={"host": "links.acme.com"})
        assert r.status_code == 200
        assert r.text == "links.acme.com"
        # X-Robots-Tag stamped on the response by middleware
        assert r.headers["X-Robots-Tag"] == "noindex, nofollow, noarchive"

    def test_custom_alias_with_password_subpath_allowed(self):
        resolver = MagicMock()
        resolver.resolve = AsyncMock(return_value=_custom_tenant())
        app = _app(resolver)

        async def password_handler(request):
            return PlainTextResponse("password-ok")

        app.routes.append(Route("/{alias}/password", password_handler))
        from starlette.testclient import TestClient

        with TestClient(app) as client:
            r = client.get("/abc/password", headers={"host": "links.acme.com"})
        assert r.status_code == 200

    def test_custom_robots_txt_inline_disallow(self):
        resolver = MagicMock()
        resolver.resolve = AsyncMock(return_value=_custom_tenant())
        with _client(resolver) as client:
            r = client.get("/robots.txt", headers={"host": "links.acme.com"})
        assert r.status_code == 200
        assert "Disallow: /" in r.text
        assert r.headers["X-Robots-Tag"] == "noindex, nofollow, noarchive"

    def test_custom_favicon_passes_through(self):
        # Build app with explicit /favicon.ico BEFORE the catch-all /{alias}
        # so Starlette's left-to-right matcher resolves to the static handler.
        from starlette.testclient import TestClient

        async def favicon(request):
            return PlainTextResponse("favicon-bytes")

        async def alias(request):
            return PlainTextResponse("alias-fallback")

        app = Starlette(
            routes=[
                Route("/favicon.ico", favicon),
                Route("/{alias:str}", alias),
            ]
        )
        resolver = MagicMock()
        resolver.resolve = AsyncMock(return_value=_custom_tenant())
        app.state.tenant_resolver = resolver
        app.add_middleware(TenantMiddleware)

        with TestClient(app) as client:
            r = client.get("/favicon.ico", headers={"host": "links.acme.com"})
        assert r.status_code == 200
        assert r.text == "favicon-bytes"

    def test_custom_stats_suffix_blocked(self):
        # `/<alias>+` is the stats page on spoo.me. Blocked on custom tenants.
        resolver = MagicMock()
        resolver.resolve = AsyncMock(return_value=_custom_tenant())
        with _client(resolver) as client:
            r = client.get("/abc+", headers={"host": "links.acme.com"})
        assert r.status_code == 404

    def test_custom_operator_paths_blocked(self):
        resolver = MagicMock()
        resolver.resolve = AsyncMock(return_value=_custom_tenant())
        blocked_paths = (
            "/api/v1/custom-domains",
            "/api/v1/shorten",
            "/dashboard",
            "/dashboard/links",
            "/auth/login",
            "/oauth/google/start",
            "/health",
            "/report",
            "/about",
            "/contact",
            "/api-docs",
        )
        with _client(resolver) as client:
            for path in blocked_paths:
                r = client.get(path, headers={"host": "links.acme.com"})
                assert r.status_code == 404, (
                    f"expected 404 on {path}, got {r.status_code}"
                )
                assert r.headers["X-Robots-Tag"] == "noindex, nofollow, noarchive"
