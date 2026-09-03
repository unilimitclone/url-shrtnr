"""DeliveryExecutor — the Mongo claim loop that actually delivers.

Mongo-only by design: claim → render (first attempt only) →
sign → POST → record. No Redis anywhere in the retry path, which is what
lets the same class run in the click worker (prod) or embedded in the
app lifespan (self-host rungs). Atomic claims with a lease make N
concurrent executors safe; the claim query is stateless over
``next_attempt_at``, so restarts self-heal on the first loop.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode

from infrastructure.crypto import decrypt_secret
from infrastructure.logging import get_logger
from infrastructure.safe_fetch import post_public
from repositories.webhook_delivery_repository import WebhookDeliveryRepository
from repositories.webhook_endpoint_repository import WebhookEndpointRepository
from repositories.webhook_event_repository import WebhookEventRepository
from schemas.enums.webhook import DeliveryStatus, EndpointDisabledReason, WebhookStatus
from schemas.models.webhook import (
    DeliveryAttempt,
    WebhookDeliveryDoc,
    WebhookEndpointDoc,
)
from services.webhooks.renderers import Renderer
from services.webhooks.signing import (
    HEADER_ID,
    HEADER_SIGNATURE,
    HEADER_TIMESTAMP,
    sign,
)
from shared.datetime_utils import as_aware_utc

log = get_logger(__name__)

SECRET_ENC_DOMAIN = "webhook-signing-secret-v1"
USER_AGENT = "spoo.me-webhooks/1.0 (+https://spoo.me)"

# Standard Webhooks retry convention: immediate, 5s, 5m, 30m, 2h, 5h, 10h.
RETRY_SCHEDULE_SECONDS = (0, 5, 300, 1800, 7200, 18000, 36000)

# 429 handling: honor Retry-After within a ceiling, else back off a minute.
RATE_LIMIT_FALLBACK_SECONDS = 60
RATE_LIMIT_MAX_DEFER_SECONDS = 900

# Type of the on-disable hook — wiring plugs email notification in here so
# the executor never grows an email dependency.
OnDisabled = Callable[[WebhookEndpointDoc, str], Awaitable[None]]


class DeliveryExecutor:
    def __init__(
        self,
        delivery_repo: WebhookDeliveryRepository,
        endpoint_repo: WebhookEndpointRepository,
        event_repo: WebhookEventRepository,
        renderers: dict[str, Renderer],
        *,
        master_secret: str,
        delivery_timeout: float = 15.0,
        max_payload_bytes: int = 20_480,
        max_consecutive_failures: int = 10,
        poll_interval: float = 1.0,
        lease_seconds: int = 60,
        on_disabled: OnDisabled | None = None,
    ) -> None:
        self._deliveries = delivery_repo
        self._endpoints = endpoint_repo
        self._events = event_repo
        self._renderers = renderers
        self._master_secret = master_secret
        self._timeout = delivery_timeout
        self._max_bytes = max_payload_bytes
        self._max_consecutive = max_consecutive_failures
        self._poll_interval = poll_interval
        self._lease = lease_seconds
        self._on_disabled = on_disabled

    # ── Loop ─────────────────────────────────────────────────────────────

    async def run(self) -> None:
        """Long-lived task; cancellation is the shutdown path."""
        log.info("webhook_executor_started", poll_interval=self._poll_interval)
        while True:
            try:
                row = await self._deliveries.claim_due(lease_seconds=self._lease)
                if row is None:
                    await asyncio.sleep(self._poll_interval)
                    continue
                await self.attempt(row)
            except asyncio.CancelledError:
                log.info("webhook_executor_stopped")
                raise
            except Exception as exc:
                # One bad row must not kill the loop.
                log.error(
                    "webhook_executor_tick_failed",
                    error=str(exc),
                    error_type=type(exc).__name__,
                )
                await asyncio.sleep(self._poll_interval)

    # ── One attempt ──────────────────────────────────────────────────────

    async def attempt(self, row: WebhookDeliveryDoc) -> None:
        # Test sends and manual retries are single-shot: they must never
        # touch endpoint health counters or enter the retry ladder — a
        # failing test would otherwise auto-disable a real endpoint, and a
        # passing one would reset a real failure streak.
        single_shot = row.is_test or row.status != DeliveryStatus.PENDING

        endpoint = await self._endpoints.find_by_id(row.endpoint_id)
        if endpoint is None or endpoint.status == WebhookStatus.DISABLED:
            await self._fail(row, "endpoint_inactive")
            return
        if endpoint.status == WebhookStatus.PAUSED and not single_shot:
            # Paused is a temporary state the owner controls: hold the
            # delivery instead of killing it, recheck in five minutes.
            await self._deliveries.defer(row.id, delay_seconds=300)
            return

        body = row.rendered_body
        if body is None:
            body = await self._render(row, endpoint)
            if body is None:
                return  # _render already recorded the terminal failure

        try:
            headers = self._headers(row.webhook_id, body, endpoint)
        except Exception as exc:
            # Unreadable secret (e.g. SECRET_KEY rotated: AES-GCM auth fails
            # for every stored secret). Without this guard the exception
            # escapes before any attempt is recorded, the lease expires, and
            # the same row re-claims forever — a silent livelock. Terminate
            # the row and disable the endpoint loudly instead; re-enabling
            # after re-creating the endpoint (new secret) recovers.
            log.error(
                "webhook_secret_unreadable",
                endpoint_id=str(endpoint.id),
                webhook_id=row.webhook_id,
                error_type=type(exc).__name__,
            )
            await self._fail(row, "secret_unreadable")
            if not single_shot:
                await self._disable(endpoint, EndpointDisabledReason.SECRET_UNREADABLE)
            return

        started = time.monotonic()
        result = await post_public(
            self._delivery_url(endpoint),
            body,
            headers=headers,
            timeout=self._timeout,
        )
        duration_ms = int((time.monotonic() - started) * 1000)
        attempt = DeliveryAttempt(
            attempted_at=datetime.now(timezone.utc),
            status_code=result.status_code,
            duration_ms=duration_ms,
            error=result.error,
            response_body=result.body_snippet,
        )

        ok = result.status_code is not None and 200 <= result.status_code < 300
        if ok:
            await self._finish(row, attempt, DeliveryStatus.SUCCESS)
            if not single_shot:
                await self._endpoints.record_success(endpoint.id)
            log.info(
                "webhook_delivered",
                endpoint_id=str(endpoint.id),
                event_type=row.event_type,
                webhook_id=row.webhook_id,
                status_code=result.status_code,
                duration_ms=duration_ms,
                attempt=row.attempt_count + 1,
                is_test=row.is_test,
            )
            return

        if result.status_code == 429 and not single_shot:
            # Rate limiting is receiver flow control, not endpoint failure —
            # normal operation for Discord/Slack receivers. Hold the row
            # without burning a ladder attempt or touching the streak; the
            # delivery-log TTL is the backstop for a receiver that
            # rate-limits forever, and the pending cap bounds the queue.
            delay = int(
                min(
                    result.retry_after_seconds or RATE_LIMIT_FALLBACK_SECONDS,
                    RATE_LIMIT_MAX_DEFER_SECONDS,
                )
            )
            await self._deliveries.defer(row.id, delay_seconds=delay)
            log.info(
                "webhook_delivery_rate_limited",
                endpoint_id=str(endpoint.id),
                event_type=row.event_type,
                webhook_id=row.webhook_id,
                delay_seconds=delay,
            )
            return

        log.warning(
            "webhook_delivery_attempt_failed",
            endpoint_id=str(endpoint.id),
            event_type=row.event_type,
            webhook_id=row.webhook_id,
            status_code=result.status_code,
            error=result.error,
            duration_ms=duration_ms,
            attempt=row.attempt_count + 1,
        )

        if single_shot:
            # One recorded attempt, terminal, health untouched: the caller
            # (test send / manual retry) reads the outcome synchronously.
            await self._finish(row, attempt, DeliveryStatus.FAILED)
            return

        if result.status_code == 410:
            await self._finish(row, attempt, DeliveryStatus.FAILED)
            await self._disable(endpoint, EndpointDisabledReason.GONE)
            return

        # attempt_count on the claimed row predates this attempt.
        attempts_done = row.attempt_count + 1
        if attempts_done >= len(RETRY_SCHEDULE_SECONDS):
            await self._finish(row, attempt, DeliveryStatus.FAILED)
            reason = result.error or f"status {result.status_code}"
            streak = await self._endpoints.record_exhausted(endpoint.id, reason)
            if streak >= self._max_consecutive:
                await self._disable(
                    endpoint, EndpointDisabledReason.CONSECUTIVE_FAILURES
                )
            return

        delay = RETRY_SCHEDULE_SECONDS[attempts_done]
        await self._deliveries.record_attempt_and_reschedule(
            row.id,
            attempt,
            datetime.now(timezone.utc) + timedelta(seconds=delay),
        )

    # ── Terminal writes ──────────────────────────────────────────────────

    async def _finish(
        self, row: WebhookDeliveryDoc, attempt: DeliveryAttempt, status: DeliveryStatus
    ) -> None:
        if await self._deliveries.record_attempt_and_finish(row.id, attempt, status):
            await self._release_slot(row)

    async def _fail(self, row: WebhookDeliveryDoc, reason: str) -> None:
        if await self._deliveries.mark_failed(row.id, reason):
            await self._release_slot(row)

    async def _release_slot(self, row: WebhookDeliveryDoc) -> None:
        # Test sends are inserted PENDING without a dispatch reservation.
        if not row.is_test:
            await self._endpoints.release_pending(row.endpoint_id)

    # ── Internals ────────────────────────────────────────────────────────

    def _delivery_url(self, endpoint: WebhookEndpointDoc) -> str:
        """Endpoint URL plus any query params the flavor's renderer
        declares (Discord's components-v2 bodies need
        ``with_components=true``). The signature covers the body alone,
        so delivery mechanics can ride the URL."""
        renderer = self._renderers.get(endpoint.flavor.value)
        query = getattr(renderer, "url_query", None)
        if not query:
            return endpoint.url
        return endpoint.url + ("&" if "?" in endpoint.url else "?") + urlencode(query)

    async def _render(
        self, row: WebhookDeliveryDoc, endpoint: WebhookEndpointDoc
    ) -> str | None:
        event = await self._events.find_by_oid(row.event_oid)
        if event is None:
            # TTL race at the 30-day edge — terminal, never a crash.
            await self._fail(row, "event_expired")
            return None
        renderer = self._renderers.get(endpoint.flavor.value)
        if renderer is None:
            await self._fail(row, f"unknown_flavor:{endpoint.flavor}")
            return None
        payload = dict(event.payload)
        if row.dropped_since_last:
            payload["dropped_since_last"] = row.dropped_since_last
        # Mongo returns naive datetimes; the wire timestamp must carry its
        # UTC offset or consumers (and Discord's local-time rendering)
        # can't place it.
        body = renderer.render(
            event.event_id,
            event.type,
            as_aware_utc(event.occurred_at).isoformat(),
            payload,
        )
        if len(body.encode()) > self._max_bytes:
            await self._fail(row, "payload_over_cap")
            return None
        await self._deliveries.set_rendered_body(row.id, body)
        return body

    def _headers(
        self, webhook_id: str, body: str, endpoint: WebhookEndpointDoc
    ) -> dict[str, str]:
        """Fresh timestamp per attempt (replay protection); dual signatures
        during a rotation grace window, space-delimited per the spec."""
        ts = int(time.time())
        secret = decrypt_secret(
            endpoint.signing_secret_enc, self._master_secret, domain=SECRET_ENC_DOMAIN
        )
        signatures = [sign(webhook_id, ts, body, secret)]
        grace_expires = as_aware_utc(endpoint.previous_secret_expires_at)
        if endpoint.previous_secret_enc and (
            grace_expires and grace_expires > datetime.now(timezone.utc)
        ):
            previous = decrypt_secret(
                endpoint.previous_secret_enc,
                self._master_secret,
                domain=SECRET_ENC_DOMAIN,
            )
            signatures.append(sign(webhook_id, ts, body, previous))
        return {
            HEADER_ID: webhook_id,
            HEADER_TIMESTAMP: str(ts),
            HEADER_SIGNATURE: " ".join(signatures),
            "Content-Type": "application/json",
            "User-Agent": USER_AGENT,
        }

    async def _disable(
        self, endpoint: WebhookEndpointDoc, reason: EndpointDisabledReason
    ) -> None:
        await self._endpoints.disable(endpoint.id, reason)
        log.warning(
            "webhook_endpoint_disabled",
            endpoint_id=str(endpoint.id),
            reason=reason.value,
        )
        if self._on_disabled is not None:
            try:
                await self._on_disabled(endpoint, reason.value)
            except Exception as exc:
                log.error("webhook_disabled_notify_failed", error=str(exc))
