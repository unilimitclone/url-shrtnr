"""Evidence tools for the investigation tier — the only outbound calls
in the system.

Every tool returns FACTS as compact strings for the model's context;
judgment stays with the model, authority stays with the mapper. Each
tool owns its own timeboxing and failure shape: a dead lookup is an
absent piece of evidence ("unavailable"), never an exception into the
agent loop.

Egress rules:
- ``fetch_page`` renders via Cloudflare Browser Run — the destination
  sees a Cloudflare IP, never ours, and the result says so.
- ``resolve_chain`` sends bodyless HEAD/GET hops from this process with
  redirects OFF and an SSRF guard: every hop's host is resolved first
  and private/loopback/link-local/reserved addresses are refused, so a
  hostile redirect into our own network lands on nothing.

``build_investigation_tools`` is the factory: the agent gets plain
callables whose docstrings are their contracts (PydanticAI builds the
tool schemas from them).
"""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import socket
import ssl
from collections.abc import Callable
from dataclasses import dataclass
from html.parser import HTMLParser
from typing import ClassVar
from urllib.parse import urljoin, urlparse

import httpx

from infrastructure.browser_run import BrowserRunClient
from infrastructure.http_client import HttpClient
from infrastructure.logging import get_logger
from repositories.feed_domain_repository import FeedDomainRepository
from repositories.url_repository import UrlRepository
from services.safety.providers import WebRiskProvider
from shared.url_utils import registrable_domain

log = get_logger(__name__)

_MAX_HOPS = 10
_HOP_TIMEOUT = 5.0
_CHAIN_TIMEOUT = 20.0
_VISIBLE_TEXT_CAP = 3000
_MAX_FORMS = 4
_MAX_FORM_FIELDS = 8
_MAX_SCRIPT_HOSTS = 12
_RDAP_TIMEOUT = 8.0
_TLS_TIMEOUT = 5.0


def _host_is_private(host: str) -> bool:
    """Resolve *host* and refuse anything that lands inside our own
    network — loopback, RFC1918, link-local, reserved. DNS failures are
    treated as private (refuse): a hop we cannot vet is a hop we do not
    take."""
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        return True
    for info in infos:
        try:
            addr = ipaddress.ip_address(info[4][0])
        except ValueError:
            return True
        if not addr.is_global:
            return True
    return False


async def _host_is_private_async(host: str) -> bool:
    return await asyncio.to_thread(_host_is_private, host)


async def resolve_chain_impl(url: str) -> str:
    """Walk redirects hop by hop (redirects OFF, max 10, bodyless)."""
    lines: list[str] = []
    current = url

    async def _walk() -> None:
        nonlocal current
        async with httpx.AsyncClient(
            follow_redirects=False, timeout=_HOP_TIMEOUT
        ) as client:
            for hop in range(1, _MAX_HOPS + 1):
                parsed = urlparse(current)
                if parsed.scheme not in ("http", "https") or not parsed.hostname:
                    lines.append(f"hop {hop}: {current} — unsupported URL, stop")
                    break
                if await _host_is_private_async(parsed.hostname):
                    lines.append(
                        f"hop {hop}: {current} — resolves to a private or "
                        "unresolvable address, refused"
                    )
                    break
                try:
                    response = await client.head(current)
                    if response.status_code in (405, 501):
                        response = await client.get(current)
                except httpx.HTTPError as exc:
                    lines.append(
                        f"hop {hop}: {current} — request failed ({type(exc).__name__})"
                    )
                    break
                location = response.headers.get("location")
                if response.is_redirect and location:
                    nxt = urljoin(current, location)
                    cross = registrable_domain(
                        parsed.hostname or ""
                    ) != registrable_domain(urlparse(nxt).hostname or "")
                    lines.append(
                        f"hop {hop}: {current} → {response.status_code} → "
                        f"{nxt}{' [cross-domain]' if cross else ''}"
                    )
                    current = nxt
                    continue
                lines.append(
                    f"final: {current} → HTTP {response.status_code} "
                    f"(content-type: {response.headers.get('content-type', '?')})"
                )
                break
            else:
                lines.append(f"stopped: exceeded {_MAX_HOPS} hops")

    # wait_for, not asyncio.timeout: 3.10 support (see safe_fetch).
    try:
        await asyncio.wait_for(_walk(), timeout=_CHAIN_TIMEOUT)
    except (asyncio.TimeoutError, TimeoutError):
        lines.append("stopped: chain resolution timed out")
    lines.append(
        "note: HTTP redirects only — JS and meta redirects are invisible "
        "here; fetch_page sees where the browser actually lands."
    )
    return "\n".join(lines)


class _EvidenceHTMLParser(HTMLParser):
    """Trim a page to what judgment needs: title, meta description,
    forms (fields + action — the top phishing signal), external script
    hosts, and capped visible text."""

    _SKIP: ClassVar[set[str]] = {"script", "style", "noscript", "template"}

    def __init__(self) -> None:
        super().__init__()
        self.title = ""
        self.meta_description = ""
        self.forms: list[str] = []
        self.script_hosts: set[str] = set()
        self.text_parts: list[str] = []
        self.text_len = 0
        self._in_title = False
        self._skip_depth = 0
        self._form_fields: list[str] | None = None
        self._form_action = ""

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag in self._SKIP:
            self._skip_depth += 1
            if tag == "script" and a.get("src"):
                host = urlparse(a["src"]).hostname
                if host:
                    self.script_hosts.add(host)
            return
        if tag == "title":
            self._in_title = True
        elif tag == "meta" and a.get("name", "").lower() == "description":
            self.meta_description = a.get("content", "")[:300]
        elif tag == "form":
            self._form_fields = []
            self._form_action = a.get("action", "")
        elif tag == "input" and self._form_fields is not None:
            kind = a.get("type", "text")
            name = a.get("name", a.get("id", "?"))
            self._form_fields.append(f"{kind}:{name}")

    def handle_endtag(self, tag):
        if tag in self._SKIP and self._skip_depth:
            self._skip_depth -= 1
        elif tag == "title":
            self._in_title = False
        elif tag == "form" and self._form_fields is not None:
            # Hidden inputs are CSRF/telemetry noise — their COUNT matters
            # (a form is real), their names never decide a verdict.
            shown = [f for f in self._form_fields if not f.startswith("hidden:")]
            hidden = len(self._form_fields) - len(shown)
            summary = ", ".join(shown[:_MAX_FORM_FIELDS]) or "none"
            if len(shown) > _MAX_FORM_FIELDS:
                summary += f", +{len(shown) - _MAX_FORM_FIELDS} more"
            if hidden:
                summary += f", {hidden} hidden"
            self.forms.append(
                f"action={self._form_action or '(same page)'} fields=[{summary}]"
            )
            self._form_fields = None

    def handle_data(self, data):
        if self._skip_depth:
            return
        if self._in_title:
            self.title += data.strip()[:200]
            return
        text = " ".join(data.split())
        if text and self.text_len < _VISIBLE_TEXT_CAP:
            self.text_parts.append(text)
            self.text_len += len(text) + 1


def trim_html(html: str) -> str:
    """Render a page down to the judgment surface, under a token budget.

    Every section is capped. Real login pages carry several forms of a
    dozen hidden CSRF/telemetry fields each, and uncapped that single
    line dwarfs the rest of the evidence — measured at 60k tokens for one
    investigation before these caps. What decides phishing is the form's
    ACTION and whether it carries a password field, not the names of its
    hidden inputs, so hidden fields are counted rather than listed.
    """
    parser = _EvidenceHTMLParser()
    # Tolerate hostile markup — keep whatever parsed before the choke.
    with contextlib.suppress(Exception):
        parser.feed(html)
    visible = " ".join(parser.text_parts)[:_VISIBLE_TEXT_CAP]
    forms = parser.forms[:_MAX_FORMS]
    if len(parser.forms) > _MAX_FORMS:
        forms.append(f"(+{len(parser.forms) - _MAX_FORMS} more forms)")
    hosts = sorted(parser.script_hosts)[:_MAX_SCRIPT_HOSTS]
    if len(parser.script_hosts) > _MAX_SCRIPT_HOSTS:
        hosts.append(f"(+{len(parser.script_hosts) - _MAX_SCRIPT_HOSTS} more)")
    parts = [
        f"title: {parser.title or '(none)'}",
        f"meta description: {parser.meta_description or '(none)'}",
        f"forms: {'; '.join(forms) or 'none'}",
        f"external script hosts: {', '.join(hosts) or 'none'}",
        f"visible text (capped): {visible or '(none)'}",
    ]
    return "\n".join(parts)


async def domain_intel_impl(http: HttpClient, host: str) -> str:
    """RDAP age + registrar, TLS issuer + cert age, MX presence. All
    best-effort and independently timeboxed — partial results are fine."""
    apex = registrable_domain(host) or host
    lines: list[str] = [f"domain: {apex}"]

    # RDAP via the bootstrap aggregator.
    try:
        response = await http.get(
            f"https://rdap.org/domain/{apex}", timeout=_RDAP_TIMEOUT
        )
        if response.status_code == 200:
            data = response.json()
            registrar = ""
            for ent in data.get("entities", []):
                if "registrar" in (ent.get("roles") or []):
                    vcard = ent.get("vcardArray", [None, []])[1]
                    for item in vcard:
                        if item[0] == "fn":
                            registrar = item[3]
            registered = ""
            for ev in data.get("events", []):
                if ev.get("eventAction") == "registration":
                    registered = ev.get("eventDate", "")
            lines.append(f"registered: {registered or 'unknown'}")
            lines.append(f"registrar: {registrar or 'unknown'}")
        else:
            lines.append(f"rdap: unavailable (HTTP {response.status_code})")
    except Exception as exc:
        lines.append(f"rdap: unavailable ({type(exc).__name__})")

    # TLS certificate (issuer + notBefore), direct handshake.
    def _tls() -> str:
        ctx = ssl.create_default_context()
        with (
            socket.create_connection((host, 443), timeout=_TLS_TIMEOUT) as sock,
            ctx.wrap_socket(sock, server_hostname=host) as tls,
        ):
            cert = tls.getpeercert()
        issuer = dict(x[0] for x in cert.get("issuer", ()) if x)
        return (
            f"tls issuer: {issuer.get('organizationName', 'unknown')}; "
            f"cert valid from: {cert.get('notBefore', 'unknown')}"
        )

    try:
        lines.append(await asyncio.to_thread(_tls))
    except Exception as exc:
        lines.append(f"tls: unavailable ({type(exc).__name__})")

    # MX presence — a "bank" with no mail is its own signal.
    try:
        import dns.asyncresolver

        answers = await dns.asyncresolver.resolve(apex, "MX", lifetime=5.0)
        lines.append(f"mx records: {len(list(answers))}")
    except Exception:
        lines.append("mx records: none found")

    return "\n".join(lines)


@dataclass
class InvestigationToolDeps:
    """What the tool factory needs from its host process."""

    browser: BrowserRunClient
    http: HttpClient
    feed_repo: FeedDomainRepository
    web_risk: WebRiskProvider | None = None
    url_repo: UrlRepository | None = None


def build_investigation_tools(deps: InvestigationToolDeps) -> list[Callable]:
    """The agent's evidence tools, closed over their dependencies. The
    docstrings ARE the tool contracts the model sees."""

    async def resolve_chain(url: str) -> str:
        """Follow the URL's HTTP redirect chain hop by hop and report the
        facts: each hop's status code, where it points, cross-domain
        moves, and the final URL with its status. Redirects prove nothing
        by themselves; use this to find the terminal destination. JS and
        meta-refresh redirects are invisible here — use fetch_page for
        where a real browser lands."""
        return await resolve_chain_impl(url)

    async def fetch_page(url: str) -> str:
        """Render the URL in a sandboxed browser (egress: Cloudflare
        datacenter IP — a cloaking page may serve scanners a clean
        version) and return the page's trimmed content: title, meta
        description, every form with its fields and action, external
        script hosts, and the visible text. Fetch the destination page
        AND, separately, the domain root (https://<host>/) — the root is
        what separates a real business with one compromised path from a
        parked or purpose-built domain."""
        result = await deps.browser.snapshot(url)
        if result is None:
            return (
                "render unavailable for this URL (page failed to load or is "
                "unreachable) — do NOT retry it; treat as missing evidence, "
                "not as evidence of being clean"
            )
        trimmed = trim_html(result.html)
        return f"rendered via {result.egress}\nurl: {url}\n{trimmed}"

    async def domain_intel(host: str) -> str:
        """Registration facts for the host's registrable domain: RDAP
        registration date and registrar, TLS certificate issuer and
        validity start, and MX record presence. A domain days old with a
        fresh certificate imitating an established brand is strong
        evidence; an old domain with stable infrastructure usually means
        a compromised legitimate site rather than a purpose-built one."""
        return await domain_intel_impl(deps.http, host)

    async def feed_lookup(host: str) -> str:
        """Check a host against the threat feeds and Google Web Risk.
        Use this on the TERMINAL host of a redirect chain — the create
        gate only ever saw the first hop. A hit here is a hard external
        signal, not a judgment call."""
        apex = registrable_domain(host) or host
        hits: list[str] = []
        for feed in ("manual", "fishfish", "shorteners"):
            try:
                if await deps.feed_repo.contains(feed, apex):
                    hits.append(f"feed:{feed}")
            except Exception as exc:
                log.warning("feed_lookup_failed", feed=feed, error=str(exc))
        if deps.web_risk is not None:
            try:
                verdict = await deps.web_risk.analyze(f"https://{host}/", host, apex)
                if verdict is not None:
                    hits.append(f"web_risk:{verdict.reason}")
            except Exception as exc:
                log.warning("web_risk_lookup_failed", error=str(exc))
        if hits:
            return f"HARD HITS on {host}: {', '.join(hits)}"
        return f"no feed or Web Risk hits on {host}"

    async def host_usage(host: str) -> str:
        """How widely this host is used across the shortener, and how much
        of it is already blocked. Call this BEFORE concluding that a whole
        host is abusive. Many links across many distinct URLs from many
        distinct creators means a shared platform (site builders, raw file
        hosts, document services) where one abusive page says nothing about
        the platform — the right scope there is a path pattern, not the
        host. A host whose links are a handful of URLs from one anonymous
        creator, or one with many already-blocked links, is the opposite."""
        if deps.url_repo is None:
            return "host usage unavailable"
        b = await deps.url_repo.host_breadth(host)
        lines = [
            f"host: {host}",
            f"links pointing here: {b['total_links']} "
            f"({b['blocked_links']} already blocked)",
            f"distinct destination URLs: {b['distinct_urls']}",
            f"distinct creators: {b['distinct_creators']}",
        ]
        if b["sample_urls"]:
            lines.append("sample of the URLs used:")
            lines.extend(f"  - {u}" for u in b["sample_urls"])
        return "\n".join(lines)

    return [resolve_chain, fetch_page, domain_intel, feed_lookup, host_usage]
