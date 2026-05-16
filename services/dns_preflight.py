"""Pre-register DNS checks. Resolve customer's CNAME + detect CF-as-DNS
authoritative so we never call CF SaaS for unpropagated records (avoids
CF's 15-min retry backoff)."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass

import dns.asyncresolver
import dns.exception
import dns.resolver

from infrastructure.logging import get_logger

log = get_logger(__name__)

_DNS_TIMEOUT_SECS = 3.0
_PUBLIC_RESOLVERS = (("1.1.1.1", "1.0.0.1"), ("8.8.8.8", "8.8.4.4"))


@dataclass(frozen=True)
class PreflightResult:
    ok: bool
    reason: str = ""


async def check_cname(fqdn: str, expected_target: str) -> PreflightResult:
    """Resolve *fqdn* CNAME at each public resolver; pass if any matches *expected_target*."""
    target = expected_target.strip(".").lower()
    results = await asyncio.gather(
        *(_query_one(fqdn, resolver_ips) for resolver_ips in _PUBLIC_RESOLVERS),
        return_exceptions=False,
    )
    matched: list[str] = []
    seen_targets: list[str] = []
    for resolver_ips, observed in zip(_PUBLIC_RESOLVERS, results, strict=True):
        if observed is None:
            continue
        seen_targets.extend(observed)
        if target in observed:
            matched.append(resolver_ips[0])
    if matched:
        return PreflightResult(ok=True)
    if not seen_targets:
        return PreflightResult(
            ok=False,
            reason=(
                f"{fqdn}: no CNAME visible at public resolvers yet. DNS may "
                f"still be propagating — retry in a few minutes."
            ),
        )
    return PreflightResult(
        ok=False,
        reason=(
            f"{fqdn}: CNAME currently resolves to {sorted(set(seen_targets))!r}, "
            f"expected {target!r}. Fix the record at your DNS provider."
        ),
    )


async def _query_one(fqdn: str, nameservers: tuple[str, ...]) -> list[str] | None:
    """Resolve fqdn's CNAME via the given nameservers. None on transport error."""
    resolver = dns.asyncresolver.Resolver(configure=False)
    resolver.nameservers = list(nameservers)
    resolver.lifetime = _DNS_TIMEOUT_SECS
    try:
        answer = await asyncio.wait_for(
            resolver.resolve(fqdn, "CNAME"),
            timeout=_DNS_TIMEOUT_SECS,
        )
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    except (dns.exception.Timeout, asyncio.TimeoutError, dns.exception.DNSException):
        return None
    return [str(rdata.target).rstrip(".").lower() for rdata in answer]


async def uses_cloudflare_dns(fqdn: str) -> bool:
    """True if fqdn's authoritative NS is CF. Customer must grey-cloud
    their records or CF SaaS validation fails."""
    resolver = dns.asyncresolver.Resolver(configure=False)
    resolver.nameservers = [ip for ips in _PUBLIC_RESOLVERS for ip in ips]
    resolver.lifetime = _DNS_TIMEOUT_SECS
    parts = fqdn.strip(".").lower().split(".")
    for i in range(len(parts) - 1):
        candidate = ".".join(parts[i:])
        try:
            answer = await asyncio.wait_for(
                resolver.resolve(candidate, "NS"),
                timeout=_DNS_TIMEOUT_SECS,
            )
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            continue
        except (
            dns.exception.Timeout,
            asyncio.TimeoutError,
            dns.exception.DNSException,
        ):
            return False
        for rdata in answer:
            target = str(rdata.target).rstrip(".").lower()
            if target.endswith(".ns.cloudflare.com"):
                return True
        return False
    return False
