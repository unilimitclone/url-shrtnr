"""CNAME-based ownership verification.

Resolves the user's fqdn and confirms it ultimately points at our edge
hostname (e.g. ``custom.spoo.me``). Recommended path for subdomains —
apex domains can't carry CNAMEs and must use ``ARecordVerifier`` instead.
"""

from __future__ import annotations

import asyncio

import dns.asyncresolver
import dns.exception
import dns.rdatatype
import dns.resolver

from infrastructure.logging import get_logger
from services.verifiers.protocol import DomainVerifier, VerificationResult

log = get_logger(__name__)

# Per-query DNS timeout. Kept short so a single slow nameserver can't stall
# the worker; total budget = timeout * dnspython retries (default 2).
_DNS_TIMEOUT_SECS = 3.0


class CnameVerifier(DomainVerifier):
    def __init__(self, cname_target: str) -> None:
        # Canonical target lowercased + trailing-dot stripped so equality
        # checks against dnspython's normalised output succeed.
        self._target = cname_target.lower().rstrip(".")

    async def verify(self, fqdn: str, token: str | None = None) -> VerificationResult:
        try:
            answer = await asyncio.wait_for(
                dns.asyncresolver.resolve(fqdn, "CNAME"),
                timeout=_DNS_TIMEOUT_SECS,
            )
        except dns.resolver.NXDOMAIN:
            return VerificationResult(False, f"{fqdn}: NXDOMAIN")
        except dns.resolver.NoAnswer:
            return VerificationResult(
                False,
                f"{fqdn}: no CNAME record found — set CNAME -> {self._target}",
            )
        except (dns.exception.Timeout, asyncio.TimeoutError):
            return VerificationResult(False, f"{fqdn}: DNS lookup timed out")
        except dns.exception.DNSException as exc:
            return VerificationResult(False, f"{fqdn}: DNS error: {exc}")

        # rrset is a sequence of CNAME RRs; usually exactly one.
        targets = [str(rdata.target).rstrip(".").lower() for rdata in answer]
        if self._target in targets:
            return VerificationResult(True)
        return VerificationResult(
            False,
            f"{fqdn}: CNAME points to {targets!r}, expected {self._target!r}",
        )
