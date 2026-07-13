"""
Response DTOs for GET /api/v1/apps.

AppGrantResponse      — one connected app (active device-auth grant)
AppGrantsListResponse — GET /api/v1/apps (200)

The wire serves the spoo-landing Apps page (lib/api/apps.ts). Grants are
not scoped — a device grant acts as the full account — so the wire carries
the registry's consent ``permissions`` strings, never scope slugs
(thoughts/apps-grants-api-prd.md §2).
"""

from __future__ import annotations

from datetime import datetime, timezone

from pydantic import Field, field_serializer

from schemas.dto.base import ResponseBase
from schemas.models.app import AppEntry
from schemas.models.app_grant import AppGrantDoc


class AppGrantResponse(ResponseBase):
    """A single connected app as returned by the list endpoint."""

    id: str = Field(
        description="Grant ID (row identity — revoke keys on `app`, not this)",
        examples=["665f1c2ab7e94d0c8a1f2b3c"],
    )
    app: str = Field(
        description=(
            "App registry key (config/apps.yaml). Shares a namespace with the "
            "frontend catalogue slugs and is the `app_id` handle for "
            "POST /auth/device/revoke."
        ),
        examples=["spoo-cli"],
    )
    app_name: str = Field(
        description="Display name from the registry (falls back to `app`)",
        examples=["Spoo CLI"],
    )
    icon: str | None = Field(
        default=None,
        description="Registry icon filename, or null when the entry is gone",
        examples=["spoo-cli.svg"],
    )
    permissions: list[str] = Field(
        description="Consent-screen permission strings the user granted",
        examples=[["Access your spoo.me account", "View your analytics"]],
    )
    granted_at: datetime = Field(description="When access was granted (ISO 8601 UTC)")
    last_used_at: datetime | None = Field(
        default=None,
        description="Last token exchange/refresh by this app, null if never used",
    )

    @field_serializer("granted_at", "last_used_at")
    def _ser_as_utc(self, dt: datetime | None) -> str | None:
        # PyMongo returns naive datetimes; without explicit tzinfo the JSON
        # form omits the offset and clients parse it as local time. Stamp
        # UTC so the wire format is unambiguous (`...+00:00`).
        if dt is None:
            return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.isoformat()

    @classmethod
    def from_grant(cls, doc: AppGrantDoc, entry: AppEntry | None) -> AppGrantResponse:
        # A grant can outlive its registry entry; it still holds live tokens,
        # so it is listed with fallback labels rather than hidden. The
        # permissions fallback must never read as "no access": the grant is
        # full-account regardless of what the catalogue once said.
        return cls(
            id=str(doc.id),
            app=doc.app_id,
            app_name=entry.name if entry else doc.app_id,
            icon=entry.icon if entry else None,
            permissions=(
                list(entry.permissions)
                if entry
                else ["Full access to your spoo.me account"]
            ),
            granted_at=doc.granted_at,
            last_used_at=doc.last_used_at,
        )


class AppGrantsListResponse(ResponseBase):
    """Response body for GET /api/v1/apps."""

    items: list[AppGrantResponse] = Field(
        description="Active grants, newest granted_at first"
    )
