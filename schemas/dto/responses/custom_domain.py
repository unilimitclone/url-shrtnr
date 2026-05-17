"""Response DTOs for the custom-domain API."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import Field

from schemas.dto.base import ResponseBase
from schemas.enums.domain_status import DomainStatus, VerificationMethod
from schemas.models.custom_domain import CustomDomainDoc


class DnsRecord(ResponseBase):
    """One DNS record the user must publish to complete setup."""

    type: Literal["CNAME", "TXT", "A"] = Field(description="Record type.")
    name: str = Field(description="Record name (subdomain or @ for apex).")
    value: str = Field(description="Record value.")
    purpose: str | None = Field(
        default=None,
        description="Human-readable note explaining why this record is needed.",
    )


class CustomDomainResponse(ResponseBase):
    """A single custom domain — covers create, get, verify, and list responses."""

    id: str = Field(description="Server-generated domain ID.")
    fqdn: str = Field(description="Canonical fqdn (lowercased, trailing dot stripped).")
    status: DomainStatus
    verification_method: VerificationMethod
    dns_records: list[DnsRecord] = Field(
        default_factory=list,
        description="DNS records the user must publish at their DNS provider.",
    )
    setup_notes: list[str] = Field(
        default_factory=list,
        description="Human-readable setup warnings/instructions specific to this domain.",
    )
    created_at: datetime
    updated_at: datetime | None = None
    last_verified_at: datetime | None = None
    last_verification_error: str | None = None

    @classmethod
    def from_doc(cls, doc: CustomDomainDoc) -> CustomDomainResponse:
        return cls(
            id=str(doc.id),
            fqdn=doc.fqdn,
            status=doc.status,
            verification_method=doc.verification_method,
            dns_records=[DnsRecord(**r) for r in doc.dns_instructions],
            setup_notes=list(doc.setup_notes),
            created_at=doc.created_at,
            updated_at=doc.updated_at,
            last_verified_at=doc.last_verified_at,
            last_verification_error=doc.last_verification_error,
        )


class CustomDomainListResponse(ResponseBase):
    """Paginated list of the caller's custom domains."""

    items: list[CustomDomainResponse]
    page: int
    page_size: int = Field(alias="pageSize")
    total: int
    has_next: bool = Field(alias="hasNext")


class CustomDomainDeleteResponse(ResponseBase):
    """Response for domain revoke. ``urls_deleted`` is 0 unless cascade was true."""

    id: str = Field(description="ID of the revoked domain.")
    fqdn: str = Field(description="The revoked fqdn.")
    cascade: bool = Field(description="Whether URLs on the domain were also deleted.")
    urls_deleted: int = Field(
        description="URL count deleted by cascade (0 when cascade=false)."
    )
