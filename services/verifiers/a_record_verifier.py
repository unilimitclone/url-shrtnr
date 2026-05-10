"""A-record-based ownership verification.

For apex domains (e.g. ``acme.com``) which can't carry CNAMEs. Confirms
the user's fqdn resolves to one of our configured origin IPv4 addresses.
Locks the rollout to a known origin IP — multi-region later requires
anycast or DNS migration.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterable

import dns.asyncresolver
import dns.exception
import dns.resolver

from services.verifiers.protocol import DomainVerifier, VerificationResult

_DNS_TIMEOUT_SECS = 3.0


class ARecordVerifier(DomainVerifier):
    def __init__(self, origin_ipv4: Iterable[str]) -> None:
        # Stored as a frozenset for O(1) membership and to make the verifier
        # immutable after construction (no risk of stray mutation).
        self._origin_ipv4: frozenset[str] = frozenset(
            ip.strip() for ip in origin_ipv4 if ip.strip()
        )
        if not self._origin_ipv4:
            raise ValueError(
                "ARecordVerifier requires at least one origin IPv4 address"
            )

    async def verify(self, fqdn: str, token: str | None = None) -> VerificationResult:
        try:
            answer = await asyncio.wait_for(
                dns.asyncresolver.resolve(fqdn, "A"),
                timeout=_DNS_TIMEOUT_SECS,
            )
        except dns.resolver.NXDOMAIN:
            return VerificationResult(False, f"{fqdn}: NXDOMAIN")
        except dns.resolver.NoAnswer:
            expected = ", ".join(sorted(self._origin_ipv4))
            return VerificationResult(
                False,
                f"{fqdn}: no A record found — set A -> {expected}",
            )
        except (dns.exception.Timeout, asyncio.TimeoutError):
            return VerificationResult(False, f"{fqdn}: DNS lookup timed out")
        except dns.exception.DNSException as exc:
            return VerificationResult(False, f"{fqdn}: DNS error: {exc}")

        # ANY one of the A records matching one of our origins is enough —
        # users may have additional A records pointing elsewhere (CDN
        # warm-up, fallback IP, etc.) and we don't want to penalise that.
        addresses = {str(rdata.address) for rdata in answer}
        if addresses & self._origin_ipv4:
            return VerificationResult(True)

        expected = ", ".join(sorted(self._origin_ipv4))
        return VerificationResult(
            False,
            f"{fqdn}: A records {sorted(addresses)!r} do not include any of "
            f"the expected origin IPs ({expected})",
        )
