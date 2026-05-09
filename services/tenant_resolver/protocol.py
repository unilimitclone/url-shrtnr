"""TenantResolver protocol — Host header → tenant info, hot-path cached.

The middleware (PR4) calls ``resolve(host)`` on every request and stamps
``request.state.domain`` so downstream handlers can scope queries by
tenant. Returning ``None`` means "this host is not a known tenant" and
the route layer should 404.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from bson import ObjectId

from schemas.enums.domain_status import DomainStatus


@dataclass(frozen=True)
class TenantInfo:
    """Resolved tenant identity for a Host header."""

    domain_id: ObjectId | None  # None for the system default
    fqdn: str
    owner_id: ObjectId | None  # None for the system default (anonymous owner)
    status: DomainStatus
    is_system_default: bool


class TenantResolver(Protocol):
    async def resolve(self, host: str) -> TenantInfo | None:
        """Return tenant info for a Host header, or None if unknown."""
        ...
