"""Tests for og:image ingestion (data-URI uploads → R2)."""

from __future__ import annotations

import base64
import struct
import zlib
from unittest.mock import AsyncMock, MagicMock

import pytest
from bson import ObjectId

from errors import ValidationError
from services.meta_tags.images import IngestedImage, ingest_meta_image

OWNER = ObjectId("aaaaaaaaaaaaaaaaaaaaaaaa")
MAX = 512_000


def _png_bytes(width=3, height=2) -> bytes:
    ihdr = struct.pack(">II", width, height) + b"\x08\x06\x00\x00\x00"
    chunk = (
        struct.pack(">I", 13)
        + b"IHDR"
        + ihdr
        + struct.pack(">I", zlib.crc32(b"IHDR" + ihdr))
    )
    return b"\x89PNG\r\n\x1a\n" + chunk


def _data_uri(data: bytes, mime="image/png") -> str:
    return f"data:{mime};base64,{base64.b64encode(data).decode()}"


def _storage(configured=True) -> MagicMock:
    s = MagicMock()
    s.is_configured = configured
    s.put_object = AsyncMock(return_value="https://og.spoo.me/og/x/abc.png")
    return s


class TestIngest:
    @pytest.mark.asyncio
    async def test_https_url_passes_through(self):
        result = await ingest_meta_image(
            "https://example.com/og.png", owner_id=OWNER, storage=None, max_bytes=MAX
        )
        assert result == IngestedImage(
            url="https://example.com/og.png", r2_hosted=False, image_meta=None
        )

    @pytest.mark.asyncio
    async def test_valid_png_data_uri_uploads(self):
        storage = _storage()
        result = await ingest_meta_image(
            _data_uri(_png_bytes(3, 2)), owner_id=OWNER, storage=storage, max_bytes=MAX
        )
        assert result.r2_hosted is True
        assert result.url == "https://og.spoo.me/og/x/abc.png"
        assert result.image_meta["width"] == 3
        assert result.image_meta["height"] == 2
        assert result.image_meta["content_type"] == "image/png"
        key = storage.put_object.call_args.args[0]
        assert key.startswith(f"og/{OWNER}/") and key.endswith(".png")

    @pytest.mark.asyncio
    async def test_magic_mismatch_rejected(self):
        # Declared jpeg, bytes are PNG — the security gate.
        storage = _storage()
        with pytest.raises(ValidationError):
            await ingest_meta_image(
                _data_uri(_png_bytes(), mime="image/jpeg"),
                owner_id=OWNER,
                storage=storage,
                max_bytes=MAX,
            )
        storage.put_object.assert_not_called()

    @pytest.mark.asyncio
    async def test_svg_data_uri_rejected_by_regex(self):
        with pytest.raises(ValidationError):
            await ingest_meta_image(
                "data:image/svg+xml;base64,PHN2Zy8+",
                owner_id=OWNER,
                storage=_storage(),
                max_bytes=MAX,
            )

    @pytest.mark.asyncio
    async def test_oversize_rejected_before_decode(self):
        big = _data_uri(b"\x89PNG\r\n\x1a\n" + b"0" * 600_000)
        with pytest.raises(ValidationError):
            await ingest_meta_image(
                big, owner_id=OWNER, storage=_storage(), max_bytes=MAX
            )

    @pytest.mark.asyncio
    async def test_bad_base64_rejected(self):
        with pytest.raises(ValidationError):
            await ingest_meta_image(
                "data:image/png;base64,!!!notb64",
                owner_id=OWNER,
                storage=_storage(),
                max_bytes=MAX,
            )

    @pytest.mark.asyncio
    async def test_unconfigured_storage_rejects_uploads_with_clear_error(self):
        with pytest.raises(ValidationError) as exc:
            await ingest_meta_image(
                _data_uri(_png_bytes()),
                owner_id=OWNER,
                storage=_storage(configured=False),
                max_bytes=MAX,
            )
        assert "not available" in str(exc.value)

    @pytest.mark.asyncio
    async def test_none_storage_rejects_uploads(self):
        with pytest.raises(ValidationError):
            await ingest_meta_image(
                _data_uri(_png_bytes()), owner_id=OWNER, storage=None, max_bytes=MAX
            )
