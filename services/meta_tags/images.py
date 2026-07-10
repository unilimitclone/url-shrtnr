"""og:image ingestion for custom meta-tags.

``meta_tags.image`` accepts either an https URL (passthrough — the async
validator checks it out-of-band, Phase C3) or a base64 data URI, which is
decoded, magic-byte validated, and uploaded to R2. Self-hosting the bytes
is the abuse control: we can scan and take down what we host, and a
hosted image can't be swapped after validation (the TOCTOU hole external
URLs have).
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from errors import ValidationError
from infrastructure.logging import get_logger
from shared.image_sniff import EXT, MIME, sniff_image

if TYPE_CHECKING:
    from bson import ObjectId

    from infrastructure.storage.r2 import R2StorageClient

log = get_logger(__name__)

_DATA_URI_RE = re.compile(
    r"^data:image/(?P<fmt>png|jpeg|webp);base64,(?P<b64>[A-Za-z0-9+/=]+)$"
)


@dataclass(frozen=True)
class IngestedImage:
    url: str  # what gets stored in meta_tags.image
    r2_hosted: bool  # True ⇒ validated synchronously here, skip the async job
    image_meta: dict | None  # {width,height,bytes,content_type,checked_at} | None


def owner_key_prefix(owner_id: ObjectId, secret: str) -> str:
    """Stable, non-reversible per-owner path segment for storage keys.

    Raw ObjectIds must not appear in public image URLs — they embed the
    account's creation timestamp and let anyone correlate a user's links.
    HMAC keeps the properties the prefix exists for (per-owner takedown
    sweeps, cross-owner overwrite isolation, idempotent dedup) without
    exposing the id. Rotating SECRET_KEY re-keys future uploads; sweeps
    of pre-rotation objects need the old secret.
    """
    digest = hmac.new(secret.encode(), str(owner_id).encode(), hashlib.sha256)
    return digest.hexdigest()[:16]


async def ingest_meta_image(
    value: str,
    *,
    owner_id: ObjectId,
    storage: R2StorageClient | None,
    max_bytes: int,
    key_secret: str = "",
) -> IngestedImage:
    """Resolve a client-supplied image value to a stored https URL."""
    if value.startswith("https://"):
        return IngestedImage(url=value, r2_hosted=False, image_meta=None)

    m = _DATA_URI_RE.match(value)
    if m is None:
        raise ValidationError(
            "image must be an https URL or a base64 data URI "
            "(image/png, image/jpeg, image/webp)",
            field="meta_tags.image",
        )
    if storage is None or not storage.is_configured:
        # Self-host degradation contract: https URLs keep working.
        raise ValidationError(
            "Image upload is not available on this deployment — "
            "host the image yourself and pass an https URL",
            field="meta_tags.image",
        )
    if len(m["b64"]) > (max_bytes * 4) // 3 + 4:  # cheap pre-decode gate
        raise ValidationError(
            f"image exceeds {max_bytes} bytes", field="meta_tags.image"
        )
    try:
        data = base64.b64decode(m["b64"], validate=True)
    except binascii.Error:
        raise ValidationError(
            "image data URI is not valid base64", field="meta_tags.image"
        ) from None
    if len(data) > max_bytes:
        raise ValidationError(
            f"image exceeds {max_bytes} bytes", field="meta_tags.image"
        )

    info = sniff_image(data)
    declared_mime = f"image/{m['fmt']}"
    if info is None or MIME[info.format] != declared_mime:
        # Magic bytes are the security gate — the declared type must match
        # what the bytes actually are.
        raise ValidationError(
            "image bytes do not match the declared image type",
            field="meta_tags.image",
        )

    # Content-addressed + owner-scoped: idempotent re-uploads dedupe, and
    # abuse takedowns can prefix-sweep og/{prefix}/. Old objects are not
    # deleted on replace (orphan GC is future work; orphans are pennies).
    prefix = owner_key_prefix(owner_id, key_secret)
    key = f"og/{prefix}/{hashlib.sha256(data).hexdigest()}.{EXT[info.format]}"
    url = await storage.put_object(key, data, content_type=declared_mime)
    log.info(
        "meta_image_uploaded",
        owner_id=str(owner_id),
        bytes=len(data),
        format=info.format,
    )
    return IngestedImage(
        url=url,
        r2_hosted=True,
        image_meta={
            "width": info.width,
            "height": info.height,
            "bytes": len(data),
            "content_type": declared_mime,
            "checked_at": datetime.now(timezone.utc),
        },
    )
