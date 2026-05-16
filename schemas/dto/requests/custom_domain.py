"""Request DTOs for the custom-domain API."""

from __future__ import annotations

from typing import Any

from pydantic import Field, field_validator

from schemas.dto.base import RequestBase
from shared.url_utils import normalise_fqdn


class CreateCustomDomainRequest(RequestBase):
    """Body for ``POST /api/v1/custom-domains``."""

    fqdn: str = Field(
        max_length=253,
        description="The fully-qualified domain to register (e.g. links.acme.com).",
        examples=["links.acme.com"],
    )

    @field_validator("fqdn", mode="before")
    @classmethod
    def _validate_fqdn(cls, v: Any) -> str:
        return normalise_fqdn(v)


class VerifyCustomDomainRequest(RequestBase):
    """Body for ``POST /api/v1/custom-domains/{id}/verify`` — empty by design.

    Triggers a fresh verifier dispatch for the named domain. Existing fields
    on the doc (verification_method, verification_token) drive the strategy.
    """


class ListCustomDomainsQuery(RequestBase):
    """Query string for ``GET /api/v1/custom-domains``."""

    page: int = Field(default=1, ge=1, le=1000)
    page_size: int = Field(default=20, ge=1, le=100)
