"""Cloudflare R2 storage client (S3-compatible API) — httpx + SigV4.

House style follows infrastructure/cloudflare_kv.py: thin REST client on
the shared HttpClient with an ``is_configured`` gate. Deliberate contrast
with the best-effort KV client: ``put_object`` RAISES on failure — it sits
on the request path of a user write, and silently storing a broken image
URL would be worse than a 502.

Zero new dependencies: SigV4 is ~50 lines of stdlib (see shared/sigv4.py);
boto3/aioboto3 were rejected (dependency tree + lifecycle mismatch).
"""

from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING
from urllib.parse import quote, urlparse

from errors import R2StorageError
from infrastructure.logging import get_logger
from shared.sigv4 import sigv4_headers

if TYPE_CHECKING:
    from infrastructure.http_client import HttpClient

log = get_logger(__name__)


class R2StorageClient:
    def __init__(
        self,
        *,
        http_client: HttpClient,
        account_id: str | None,
        access_key_id: str | None,
        secret_access_key: str | None,
        bucket: str | None,
        public_base_url: str | None,
        endpoint_url: str | None = None,
        request_timeout_seconds: float = 15.0,
    ) -> None:
        self._http = http_client
        self._account_id = account_id
        self._access_key_id = access_key_id
        self._secret_access_key = secret_access_key
        self._bucket = bucket
        self._public_base_url = (public_base_url or "").rstrip("/")
        self._endpoint = (
            endpoint_url.rstrip("/")
            if endpoint_url
            else f"https://{account_id}.r2.cloudflarestorage.com"
        )
        self._host = urlparse(self._endpoint).netloc
        self._timeout = request_timeout_seconds

    @property
    def is_configured(self) -> bool:
        return bool(
            self._account_id
            and self._access_key_id
            and self._secret_access_key
            and self._bucket
            and self._public_base_url
        )

    def public_url(self, key: str) -> str:
        return f"{self._public_base_url}/{key}"

    async def put_object(self, key: str, data: bytes, *, content_type: str) -> str:
        """Upload and return the public URL. Raises R2StorageError on failure."""
        path = f"/{self._bucket}/{quote(key, safe='/')}"
        signed = sigv4_headers(
            method="PUT",
            host=self._host,
            path=path,
            payload_hash=hashlib.sha256(data).hexdigest(),
            access_key_id=self._access_key_id or "",
            secret_access_key=self._secret_access_key or "",
            headers={"content-type": content_type},
        )
        try:
            resp = await self._http.request(
                "PUT",
                f"{self._endpoint}{path}",
                content=data,
                headers={**signed, "content-type": content_type},
                # The shared client's 5s default is too tight for image PUTs.
                timeout=self._timeout,
            )
        except Exception as exc:
            log.error("r2_put_failed", key=key, error=str(exc))
            raise R2StorageError("Image upload failed") from exc
        if resp.status_code >= 300:
            log.error(
                "r2_put_failed",
                key=key,
                status=resp.status_code,
                body_preview=resp.text[:300],
            )
            raise R2StorageError("Image upload failed")
        log.info("r2_put_succeeded", key=key, bytes=len(data))
        return self.public_url(key)

    async def delete_object(self, key: str) -> bool:
        """Best-effort delete (takedown tooling / future GC). 404 = success."""
        path = f"/{self._bucket}/{quote(key, safe='/')}"
        signed = sigv4_headers(
            method="DELETE",
            host=self._host,
            path=path,
            payload_hash=hashlib.sha256(b"").hexdigest(),
            access_key_id=self._access_key_id or "",
            secret_access_key=self._secret_access_key or "",
        )
        try:
            resp = await self._http.request(
                "DELETE", f"{self._endpoint}{path}", headers=signed
            )
        except Exception as exc:
            log.warning("r2_delete_failed", key=key, error=str(exc))
            return False
        ok = resp.status_code < 300 or resp.status_code == 404
        if not ok:
            log.warning("r2_delete_failed", key=key, status=resp.status_code)
        return ok
