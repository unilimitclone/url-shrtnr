"""TXT-challenge ownership verification (DNS-01 style).

Resolves ``_spoo-challenge.<fqdn>`` and confirms the TXT record contains
the per-domain token issued at create time. Works for both apex domains
and subdomains and doesn't constrain the user's existing DNS layout.
"""

from __future__ import annotations

import asyncio

import dns.asyncresolver
import dns.exception
import dns.resolver

from infrastructure.logging import get_logger
from services.verifiers.protocol import DomainVerifier, VerificationResult

log = get_logger(__name__)

_DNS_TIMEOUT_SECS = 3.0
_CHALLENGE_PREFIX = "_spoo-challenge"


class TxtChallengeVerifier(DomainVerifier):
    async def verify(self, fqdn: str, token: str | None = None) -> VerificationResult:
        if not token:
            # The orchestrator is responsible for stamping a token on the doc
            # at create time when this verifier is selected; absence here is
            # a programmer error, not user error.
            return VerificationResult(
                False,
                "internal: TxtChallengeVerifier called without a token",
            )

        challenge_host = f"{_CHALLENGE_PREFIX}.{fqdn}"
        try:
            answer = await asyncio.wait_for(
                dns.asyncresolver.resolve(challenge_host, "TXT"),
                timeout=_DNS_TIMEOUT_SECS,
            )
        except dns.resolver.NXDOMAIN:
            return VerificationResult(
                False,
                f"{challenge_host}: NXDOMAIN — set TXT '{challenge_host}' = '{token}'",
            )
        except dns.resolver.NoAnswer:
            return VerificationResult(
                False,
                f"{challenge_host}: no TXT record found — set TXT = '{token}'",
            )
        except (dns.exception.Timeout, asyncio.TimeoutError):
            return VerificationResult(False, f"{challenge_host}: DNS lookup timed out")
        except dns.exception.DNSException as exc:
            return VerificationResult(False, f"{challenge_host}: DNS error: {exc}")

        # Each TXT rdata.strings is a list of byte chunks (TXT records are
        # split into 255-byte chunks at the wire). Concatenate per record,
        # decode, and compare.
        for rdata in answer:
            decoded = b"".join(rdata.strings).decode("utf-8", errors="ignore")
            if decoded == token:
                return VerificationResult(True)

        return VerificationResult(
            False,
            f"{challenge_host}: TXT records did not contain the expected "
            f"token (expected '{token}')",
        )
