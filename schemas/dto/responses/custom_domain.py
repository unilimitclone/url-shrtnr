"""Response DTOs for the custom-domain API."""

from __future__ import annotations

from datetime import datetime

from pydantic import Field

from schemas.dto.base import ResponseBase
from schemas.enums.domain_status import DomainStatus, VerificationMethod
from schemas.models.custom_domain import CustomDomainDoc


class CustomDomainResponse(ResponseBase):
    """A single custom domain — covers create, get, and verify responses."""

    id: str = Field(description="Server-generated domain ID.")
    fqdn: str = Field(description="Canonical fqdn (lowercased, trailing dot stripped).")
    status: DomainStatus
    verification_method: VerificationMethod
    # Returned only when verification_method == TXT_CHALLENGE; clients echo
    # this into a `_spoo-challenge.<fqdn>` TXT record to prove ownership.
    verification_token: str | None = None
    # Free-form, human-readable instructions for whichever verification
    # method the client picked. Built at the route layer so the message can
    # reference settings (cname target, origin IPv4 list).
    setup_instructions: str | None = None
    created_at: datetime
    updated_at: datetime | None = None
    last_verified_at: datetime | None = None
    last_verification_error: str | None = None

    @classmethod
    def from_doc(
        cls,
        doc: CustomDomainDoc,
        setup_instructions: str | None = None,
    ) -> CustomDomainResponse:
        return cls(
            id=str(doc.id),
            fqdn=doc.fqdn,
            status=doc.status,
            verification_method=doc.verification_method,
            # Surface the TXT token only when the chosen method needs it.
            verification_token=(
                doc.verification_token
                if doc.verification_method == VerificationMethod.TXT_CHALLENGE
                else None
            ),
            setup_instructions=setup_instructions,
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
