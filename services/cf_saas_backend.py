"""CfSaasBackend — single class, three protocols.

CF SaaS owns hostname registration, DCV, and cert issuance/eviction. The
three concerns map onto three protocols (HostnameRegistrar, DomainVerifier,
EdgeProvisioner) so the rest of the system stays decoupled from CF's API.
One backend implements all three because the CF hostname id ties them
together — splitting the class would force redundant CF lookups.

Wiring instantiates this once and registers the same instance in all three
protocol slots. Callers see only the protocols.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import httpx

from errors import CloudflareAPIError
from infrastructure.cloudflare_client import CloudflareClient
from infrastructure.logging import get_logger
from services.edge_provisioner.protocol import EdgeProvisioner
from services.registrar.protocol import HostnameRegistrar, RegistrationResult
from services.verifiers.protocol import DomainVerifier, VerificationResult

if TYPE_CHECKING:
    from repositories.custom_domain_repository import CustomDomainRepository

log = get_logger(__name__)


# Map our VerificationMethod string values to the CF API's "ssl.method" field.
_DCV_METHOD_MAP = {
    "cf_delegated_dcv": "txt",  # CF + delegated CNAME = auto-renewing TXT DCV
    "cf_http_dcv": "http",
}


class CfSaasBackend(HostnameRegistrar, DomainVerifier, EdgeProvisioner):
    def __init__(
        self,
        *,
        cf_client: CloudflareClient,
        custom_domain_repo: CustomDomainRepository,
        cname_target: str,
        dcv_delegation_target: str,
    ) -> None:
        self._cf = cf_client
        self._repo = custom_domain_repo
        # Strip dots so misconfigured env vars can't produce `foo..bar`.
        self._cname_target = cname_target.strip(".")
        self._dcv_delegation_target = dcv_delegation_target.strip(".")

    # ── HostnameRegistrar ───────────────────────────────────────────────

    async def register(
        self, fqdn: str, *, dcv_method: str | None = None
    ) -> RegistrationResult:
        cf_method = _DCV_METHOD_MAP.get(dcv_method or "cf_delegated_dcv", "txt")
        result = await self._cf.create_custom_hostname(fqdn, dcv_method=cf_method)
        instructions = self._build_dns_instructions(
            fqdn, dcv_method or "cf_delegated_dcv"
        )
        return RegistrationResult(
            backend_id=result.id,
            instructions=instructions,
            backend_metadata={
                "cf_status": result.status,
                "cf_ssl_status": result.ssl_status,
            },
        )

    # Teardown lives in announce_revoked (EdgeProvisioner). One backend,
    # three protocols; the CF delete call is the same operation.

    # ── DomainVerifier ──────────────────────────────────────────────────

    async def verify(self, fqdn: str, token: str | None = None) -> VerificationResult:
        # ``token`` is reused as the CF hostname id — service layer passes
        # ``doc.cf_hostname_id``. Callers without an id can't verify CF.
        if not token:
            return VerificationResult(
                verified=False,
                reason="missing cf_hostname_id; backend cannot poll CF",
            )

        try:
            result = await self._cf.get_custom_hostname(token)
        except CloudflareAPIError as exc:
            return VerificationResult(verified=False, reason=str(exc))
        except httpx.HTTPError as exc:
            return VerificationResult(verified=False, reason=f"network error: {exc}")

        verified = result.status == "active" and result.ssl_status == "active"
        if verified:
            return VerificationResult(verified=True)

        if result.verification_errors:
            reason = "; ".join(result.verification_errors)
        else:
            reason = f"status={result.status}, ssl_status={result.ssl_status}"
        return VerificationResult(verified=False, reason=reason)

    # ── EdgeProvisioner ─────────────────────────────────────────────────

    async def announce_revoked(self, fqdn: str) -> bool:
        # CF SaaS revoke = delete the custom hostname. Resolve the cf id
        # from the doc; fall back to CF name lookup if the doc lost it.
        # Protocol contract: never raise — every failure path returns False
        # so the orchestrator persists ``eviction_pending=True`` and the
        # worker retries.
        backend_id, status = await self._resolve_backend_id(fqdn)
        if status == "absent":
            log.info("cf_saas_revocation_already_absent", fqdn=fqdn)
            return True
        if status == "lookup_failed" or backend_id is None:
            return False

        try:
            await self._cf.delete_custom_hostname(backend_id)
        except CloudflareAPIError as exc:
            log.warning(
                "cf_saas_revocation_rejected",
                fqdn=fqdn,
                backend_id=backend_id,
                error=str(exc),
            )
            return False
        except Exception as exc:
            log.exception(
                "cf_saas_revocation_unexpected_error",
                fqdn=fqdn,
                backend_id=backend_id,
                error=str(exc),
            )
            return False

        log.info(
            "cf_saas_revocation_announced",
            fqdn=fqdn,
            backend_id=backend_id,
        )
        return True

    async def _resolve_backend_id(self, fqdn: str) -> tuple[str | None, str]:
        """Returns (backend_id, status) where status is one of
        ``"resolved"`` (id usable), ``"absent"`` (CF has no hostname),
        ``"lookup_failed"`` (transport error — caller should retry later).
        """
        try:
            doc = await self._repo.find_by_fqdn(fqdn)
        except Exception as exc:
            log.warning(
                "cf_saas_revoke_doc_lookup_failed",
                fqdn=fqdn,
                error=str(exc),
            )
            doc = None
        if doc is not None and doc.cf_hostname_id:
            return doc.cf_hostname_id, "resolved"

        try:
            lookup = await self._cf.find_hostname_by_fqdn(fqdn)
        except CloudflareAPIError as exc:
            log.warning(
                "cf_saas_revoke_lookup_failed",
                fqdn=fqdn,
                error=str(exc),
            )
            return None, "lookup_failed"
        if lookup is None:
            return None, "absent"
        return lookup.id, "resolved"

    # ── helpers ─────────────────────────────────────────────────────────

    def _build_dns_instructions(
        self, fqdn: str, dcv_method: str
    ) -> list[dict[str, str]]:
        # Always need the traffic-routing CNAME.
        records: list[dict[str, str]] = [
            {
                "type": "CNAME",
                "name": fqdn,
                "value": self._cname_target,
                "purpose": "routes traffic to spoo.me",
            }
        ]
        if dcv_method == "cf_delegated_dcv":
            # Delegated DCV: one extra permanent CNAME so CF auto-renews.
            records.append(
                {
                    "type": "CNAME",
                    "name": f"_acme-challenge.{fqdn}",
                    "value": f"{fqdn}.{self._dcv_delegation_target}",
                    "purpose": "auto-renews TLS certificate",
                }
            )
        # cf_http_dcv: CF runs HTTP-01 against the routing CNAME — no extra
        # record needed beyond the one above.
        return records
