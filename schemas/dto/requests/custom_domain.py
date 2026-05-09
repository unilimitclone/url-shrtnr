"""Request DTOs for the custom-domain API."""

from __future__ import annotations

import re
from typing import Any

from pydantic import Field, field_validator

from schemas.dto.base import RequestBase
from schemas.enums.domain_status import VerificationMethod

# Same regex as schemas.models.custom_domain — duplicated here so DTO
# validation rejects bad input at the API boundary without depending on
# the document model.
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)"
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z]{2,63}$"
)


def _normalise_fqdn(v: Any) -> str:
    if v is None:
        raise ValueError("fqdn is required")
    normalised = str(v).strip().lower().rstrip(".")
    if not normalised:
        raise ValueError("fqdn is required")
    if re.search(r"[\x00-\x1F\x7F-\x9F<>\"'`\\]", normalised):
        raise ValueError("fqdn contains forbidden characters")
    if not _HOSTNAME_RE.match(normalised):
        raise ValueError("fqdn does not look like a valid hostname")
    return normalised


class CreateCustomDomainRequest(RequestBase):
    """Body for ``POST /api/v1/custom-domains``."""

    fqdn: str = Field(
        max_length=253,
        description="The fully-qualified domain to register (e.g. links.acme.com).",
        examples=["links.acme.com"],
    )
    verification_method: VerificationMethod = Field(
        default=VerificationMethod.CNAME,
        description=(
            "How ownership will be proven. Pick one of: "
            "`cname` (recommended for subdomains), "
            "`a_record` (for apex domains), "
            "`txt_challenge` (DNS-01 style, works on any record)."
        ),
        examples=["cname"],
    )

    @field_validator("fqdn", mode="before")
    @classmethod
    def _validate_fqdn(cls, v: Any) -> str:
        return _normalise_fqdn(v)

    @field_validator("verification_method", mode="before")
    @classmethod
    def _reject_system_method(cls, v: Any) -> Any:
        # SYSTEM is reserved for the auto-seeded default row; users may not
        # claim it through the public API.
        if v == VerificationMethod.SYSTEM or v == "system":
            raise ValueError(
                "verification_method 'system' is reserved for internal use"
            )
        return v


class VerifyCustomDomainRequest(RequestBase):
    """Body for ``POST /api/v1/custom-domains/{id}/verify`` — empty by design.

    Triggers a fresh verifier dispatch for the named domain. Existing fields
    on the doc (verification_method, verification_token) drive the strategy.
    """


class ListCustomDomainsQuery(RequestBase):
    """Query string for ``GET /api/v1/custom-domains``."""

    page: int = Field(default=1, ge=1, le=1000)
    page_size: int = Field(default=20, ge=1, le=100)
