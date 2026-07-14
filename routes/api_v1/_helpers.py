"""Shared helpers for the api_v1 route modules.

Small route-layer utilities used by more than one router in this package.
Lives here so route modules never reach into each other for privates.
"""

from __future__ import annotations

from bson import ObjectId

from errors import ValidationError


def parse_url_id(url_id: str) -> ObjectId:
    """Parse url_id path param to ObjectId, raise 400 on invalid format."""
    try:
        return ObjectId(url_id)
    except Exception:
        raise ValidationError("Invalid URL ID format") from None
