"""
Request DTOs for account deletion.

DeleteAccountRequest   — DELETE /api/v1/me
RestoreAccountRequest  — POST /auth/restore
"""

from __future__ import annotations

from pydantic import EmailStr, Field

from schemas.dto.base import RequestBase


class DeleteAccountRequest(RequestBase):
    """Request body for DELETE /api/v1/me.

    Exactly one re-auth proof applies per account: ``password`` for
    accounts with a password set, ``confirm_email`` (the exact account
    email, typed) for OAuth-only accounts. The wrong proof — or a missing
    one — fails re-authentication; the response never says which.
    """

    password: str | None = Field(
        default=None,
        max_length=255,
        description="Account password — re-auth for accounts with a password set",
        examples=["MySecurePass123!"],
    )
    confirm_email: str | None = Field(
        default=None,
        max_length=320,
        description=(
            "The exact account email, typed to confirm — re-auth for "
            "OAuth-only accounts (no password set)"
        ),
        examples=["user@example.com"],
    )


class RestoreAccountRequest(RequestBase):
    """Request body for POST /auth/restore."""

    email: EmailStr = Field(
        description="Account email address", examples=["user@example.com"]
    )
    password: str = Field(
        max_length=255,
        description="Account password",
        examples=["MySecurePass123!"],
    )
