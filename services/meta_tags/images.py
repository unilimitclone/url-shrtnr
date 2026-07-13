"""og:image ingestion for custom meta-tags.

``meta_tags.image`` accepts either an https URL (passthrough — the async
validator checks it out-of-band, Phase C3) or a base64 data URI, which is
decoded, magic-byte validated, and uploaded to R2. Self-hosting the bytes
is the abuse control: we can scan and take down what we host, and a
hosted image can't be swapped after validation (the TOCTOU hole external
URLs have).

The decode/validation gates live in services.image_ingest — shared with
profile-picture uploads so both surfaces enforce the same posture.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from errors import ValidationError
from infrastructure.logging import get_logger
from services.image_ingest import (
    decode_image_data_uri,
    owner_key_prefix,
    split_image_data_uri,
)
from shared.image_sniff import EXT

if TYPE_CHECKING:
    from bson import ObjectId

    from infrastructure.storage.r2 import R2StorageClient

log = get_logger(__name__)


@dataclass(frozen=True)
class IngestedImage:
    url: str  # what gets stored in meta_tags.image
    r2_hosted: bool  # True ⇒ validated synchronously here, skip the async job
    image_meta: dict | None  # {width,height,bytes,content_type,checked_at} | None


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

    parts = split_image_data_uri(value)
    if parts is None:
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
    fmt, b64 = parts
    decoded = decode_image_data_uri(
        fmt, b64, max_bytes=max_bytes, field="meta_tags.image"
    )

    # Content-addressed + owner-scoped: idempotent re-uploads dedupe, and
    # abuse takedowns can prefix-sweep og/{prefix}/. Old objects are not
    # deleted on replace (orphan GC is future work; orphans are pennies).
    prefix = owner_key_prefix(owner_id, key_secret)
    digest = hashlib.sha256(decoded.data).hexdigest()
    key = f"og/{prefix}/{digest}.{EXT[decoded.info.format]}"
    url = await storage.put_object(key, decoded.data, content_type=decoded.content_type)
    log.info(
        "meta_image_uploaded",
        owner_id=str(owner_id),
        bytes=len(decoded.data),
        format=decoded.info.format,
    )
    return IngestedImage(
        url=url,
        r2_hosted=True,
        image_meta={
            "width": decoded.info.width,
            "height": decoded.info.height,
            "bytes": len(decoded.data),
            "content_type": decoded.content_type,
            "checked_at": datetime.now(timezone.utc),
        },
    )
