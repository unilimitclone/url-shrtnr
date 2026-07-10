"""SSRF-guarded outbound fetch for user-supplied URLs.

The shared HttpClient is unusable here: it hardcodes follow_redirects=True,
which would let httpx follow hops with zero per-hop validation. This module
owns its redirect loop and, per hop:

  1. requires https;
  2. resolves A+AAAA first (dnspython, precedent services/dns_preflight.py)
     and rejects unless ALL addresses are public — private/loopback/
     link-local/reserved/multicast/unspecified, with IPv4-mapped IPv6
     (::ffff:10.0.0.1) unwrapped;
  3. connects to the RESOLVED IP (host header + SNI carry the original
     name) so DNS can't rebind between check and fetch;
  4. streams the body under a hard byte cap.

Used by the async og:image validator (Phase C) and the /api/v1/metadata
destination parser (Phase D).
"""

from __future__ import annotations

import asyncio
import ipaddress
from dataclasses import dataclass

import dns.asyncresolver
import dns.exception
import httpx

from infrastructure.logging import get_logger

log = get_logger(__name__)

# Default only — deployments configure META_TAGS_FETCH_USER_AGENT (config.py).
DEFAULT_USER_AGENT = "spoo.me-og-validator/1.0 (+https://spoo.me)"
_REDIRECT_STATUSES = (301, 302, 303, 307, 308)


class FetchHardError(Exception):
    """Permanent: the URL can never validate (private IP, wrong type, 4xx…)."""


class FetchDeniedError(FetchHardError):
    """The origin refused OUR client (401/403) — typically a WAF or hotlink
    protection blocking an unrecognized User-Agent. Says nothing about
    whether the resource works for preview crawlers, whose UAs are widely
    allowlisted; callers that act on fetch results (e.g. clearing a user's
    og:image) should treat this as indeterminate, not broken."""


class FetchTransientError(Exception):
    """Retryable: timeouts, 5xx, 429, DNS timeouts."""


@dataclass(frozen=True)
class FetchedBody:
    data: bytes
    content_type: str
    final_url: str


def _is_public(ip: str) -> bool:
    addr = ipaddress.ip_address(ip)
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    # is_global (not a flag union) catches CGNAT 100.64.0.0/10 and
    # transitional ranges the union missed; exclude multicast, which is
    # is_global=True but must never be a fetch target.
    return addr.is_global and not addr.is_multicast


async def _resolve_public_ip(host: str) -> str:
    """Resolve *host* and return one address, rejecting any private result."""
    # A literal IP address skips DNS entirely.
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        if not _is_public(host):
            raise FetchHardError("address is not public")
        return host

    ips: list[str] = []
    for rdtype in ("A", "AAAA"):
        try:
            answer = await dns.asyncresolver.resolve(host, rdtype)
            ips.extend(r.to_text() for r in answer)
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            continue
        except dns.exception.Timeout as exc:
            raise FetchTransientError("DNS timeout") from exc
        except dns.exception.DNSException as exc:
            raise FetchHardError(f"DNS failure: {type(exc).__name__}") from exc
    if not ips:
        raise FetchHardError("host does not resolve")
    if not all(_is_public(ip) for ip in ips):
        # ANY private address fails the whole host — a mixed record set is
        # exactly what a rebinding/split-horizon attack looks like.
        raise FetchHardError("host resolves to a non-public address")
    return ips[0]


def _bracket(ip: str) -> str:
    return f"[{ip}]" if ":" in ip else ip


async def fetch_public(
    url: str,
    *,
    accept_content: tuple[str, ...],
    reject_content: tuple[str, ...] = (),
    timeout: float = 5.0,
    max_bytes: int = 1_048_576,
    max_redirects: int = 3,
    truncate_over_cap: bool = False,
    user_agent: str = DEFAULT_USER_AGENT,
) -> FetchedBody:
    """Fetch *url* with SSRF guards. ``accept_content`` are content-type
    prefixes (e.g. ``("image/",)``); ``reject_content`` are substrings that
    fail even when a prefix matched (e.g. ``("svg",)``).

    ``truncate_over_cap=True`` returns the first ``max_bytes`` instead of
    failing when the body exceeds the cap — right for HTML meta parsing
    (tags live in <head>; github.com's homepage alone is >512KB), wrong
    for images (a truncated image is not a valid image)."""
    # httpx timeouts are per-operation and reset each chunk; this is the
    # wall-clock ceiling a slow-drip server can't evade.
    hop_deadline = timeout * 3
    for _hop in range(max_redirects + 1):
        parsed = httpx.URL(url)
        if parsed.scheme != "https":
            raise FetchHardError("non-https URL")
        ip = await _resolve_public_ip(parsed.host)

        # Pin the connection to the validated IP; keep name-based TLS via
        # sni_hostname and the Host header.
        pinned = parsed.copy_with(host=_bracket(ip))
        async with httpx.AsyncClient(follow_redirects=False, timeout=timeout) as client:
            request = client.build_request(
                "GET",
                pinned,
                headers={
                    "Host": parsed.host,
                    "User-Agent": user_agent,
                    # No gzip: the byte cap counts decompressed bytes, so a
                    # small compressed bomb could blow past it in one read.
                    "Accept-Encoding": "identity",
                },
                extensions={"sni_hostname": parsed.host},
            )
            try:
                resp = await client.send(request, stream=True)
            except (httpx.TimeoutException, httpx.TransportError) as exc:
                raise FetchTransientError(str(exc)) from exc

            try:
                if resp.status_code in _REDIRECT_STATUSES:
                    location = resp.headers.get("location")
                    if not location:
                        raise FetchHardError("redirect without location")
                    url = str(parsed.join(location))
                    continue  # next hop re-validated from the top
                if resp.status_code >= 500 or resp.status_code == 429:
                    raise FetchTransientError(f"status {resp.status_code}")
                if resp.status_code in (401, 403):
                    raise FetchDeniedError(f"status {resp.status_code}")
                if resp.status_code != 200:
                    raise FetchHardError(f"status {resp.status_code}")

                ctype = (
                    resp.headers.get("content-type", "").split(";")[0].strip().lower()
                )
                if not ctype.startswith(accept_content):
                    raise FetchHardError(f"content-type {ctype!r}")
                if any(marker in ctype for marker in reject_content):
                    raise FetchHardError(f"content-type {ctype!r}")
                declared = resp.headers.get("content-length", "")
                if (
                    declared.isdigit()  # garbage header ≠ worker crash
                    and int(declared) > max_bytes
                    and not truncate_over_cap
                ):
                    raise FetchHardError("content-length over cap")

                buf = bytearray()
                try:
                    async with asyncio.timeout(hop_deadline):
                        async for chunk in resp.aiter_bytes():
                            buf += chunk
                            if len(buf) > max_bytes:
                                if truncate_over_cap:
                                    buf = buf[:max_bytes]
                                    break
                                raise FetchHardError("body over cap")
                except TimeoutError as exc:
                    raise FetchTransientError("read deadline exceeded") from exc
                return FetchedBody(bytes(buf), ctype, str(parsed))
            finally:
                await resp.aclose()
    raise FetchHardError("too many redirects")


async def fetch_public_image(
    url: str,
    *,
    timeout: float = 5.0,
    max_bytes: int = 1_048_576,
    max_redirects: int = 3,
    user_agent: str = DEFAULT_USER_AGENT,
) -> FetchedBody:
    return await fetch_public(
        url,
        accept_content=("image/",),
        reject_content=("svg",),
        timeout=timeout,
        max_bytes=max_bytes,
        max_redirects=max_redirects,
        user_agent=user_agent,
    )
