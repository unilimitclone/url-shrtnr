"""
Custom-domain document model.

Maps to the ``custom_domains`` collection. Each row represents either:
  - the auto-seeded system default (``is_system_default=True``,
    ``verification_method=SYSTEM``, owned by ANONYMOUS_OWNER_ID), or
  - a user-registered fqdn that moves through the ``DomainStatus`` lifecycle
    via the ``CustomDomainService`` state machine.

Validators are syntax-only — DNS resolution lives in the verifier services,
never in Pydantic.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import field_validator

from schemas.enums.domain_status import DomainStatus, VerificationMethod
from schemas.models.base import MongoBaseModel, PyObjectId
from shared.url_utils import normalise_fqdn


class CustomDomainDoc(MongoBaseModel):
    """Document model for the ``custom_domains`` collection."""

    fqdn: str
    owner_id: PyObjectId
    status: DomainStatus = DomainStatus.PENDING
    verification_method: VerificationMethod
    # Per-domain UUID4 stamped at create time when the chosen method is
    # TXT_CHALLENGE. Stored on every doc for shape uniformity; consulted only
    # by the TXT verifier.
    verification_token: str | None = None
    is_system_default: bool = False

    created_at: datetime
    updated_at: datetime | None = None
    last_verified_at: datetime | None = None
    # Free-form last failure reason — surface back to the user on re-verify
    # attempts so they can debug their DNS without contacting support.
    last_verification_error: str | None = None

    # Edge state — orthogonal to ``status``. True when the user/admin has
    # asked us to revoke or suspend but the edge (Caddy) didn't ack the
    # cert eviction.
    eviction_pending: bool = False
    last_eviction_error: str | None = None

    @field_validator("fqdn", mode="before")
    @classmethod
    def _normalise(cls, v: Any) -> str:
        return normalise_fqdn(v)


# Convenience: the set of legal state transitions, used by the service to
# reject illegal mutations (e.g. anything-out-of-REVOKED). VERIFYING is kept
# in the enum for forward compat (when verification becomes async or worker-
# coordinated) but the synchronous flow today goes straight PENDING → ACTIVE.
LEGAL_TRANSITIONS: dict[DomainStatus, frozenset[DomainStatus]] = {
    DomainStatus.PENDING: frozenset({DomainStatus.ACTIVE, DomainStatus.REVOKED}),
    DomainStatus.VERIFYING: frozenset(
        {DomainStatus.ACTIVE, DomainStatus.PENDING, DomainStatus.REVOKED}
    ),
    DomainStatus.ACTIVE: frozenset({DomainStatus.SUSPENDED, DomainStatus.REVOKED}),
    DomainStatus.SUSPENDED: frozenset({DomainStatus.ACTIVE, DomainStatus.REVOKED}),
    DomainStatus.REVOKED: frozenset(),  # terminal
}


# Re-exported here for convenience so callers don't need to import from
# schemas.enums separately.
__all__ = [
    "LEGAL_TRANSITIONS",
    "CustomDomainDoc",
    "DomainStatus",
    "VerificationMethod",
]
