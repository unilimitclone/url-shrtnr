"""DeliveryExecutor — render-once, signing headers, retry ladder, disable
paths. post_public is patched; repos are AsyncMocks shaped per call."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from bson import ObjectId

from infrastructure.crypto import encrypt_secret
from infrastructure.safe_fetch import PostResult
from schemas.enums.webhook import (
    DeliveryStatus,
    EndpointDisabledReason,
    WebhookFlavor,
    WebhookStatus,
)
from schemas.models.webhook import (
    WebhookDeliveryDoc,
    WebhookEndpointDoc,
    WebhookEventDoc,
)
from services.webhooks.executor import (
    RATE_LIMIT_FALLBACK_SECONDS,
    RATE_LIMIT_MAX_DEFER_SECONDS,
    RETRY_SCHEDULE_SECONDS,
    SECRET_ENC_DOMAIN,
    DeliveryExecutor,
)
from services.webhooks.renderers import default_renderers
from services.webhooks.signing import (
    HEADER_ID,
    HEADER_SIGNATURE,
    HEADER_TIMESTAMP,
    verify,
)

_MASTER = "test-master-secret"
_SECRET = "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw"


def _endpoint(**overrides: Any) -> WebhookEndpointDoc:
    doc = WebhookEndpointDoc(
        user_id=ObjectId(),
        url="https://example.com/hook",
        events=["*"],
        status=WebhookStatus.ACTIVE,
        flavor=WebhookFlavor.RAW,
        signing_secret_enc=encrypt_secret(_SECRET, _MASTER, domain=SECRET_ENC_DOMAIN),
        signing_secret_prefix=_SECRET[:14],
    )
    doc.id = ObjectId()
    return doc.model_copy(update=overrides)


def _delivery(**overrides: Any) -> WebhookDeliveryDoc:
    doc = WebhookDeliveryDoc(
        endpoint_id=ObjectId(),
        user_id=ObjectId(),
        event_oid=ObjectId(),
        event_type="link.clicked",
        webhook_id="msg_test",
        next_attempt_at=datetime.now(timezone.utc),
    )
    doc.id = ObjectId()
    return doc.model_copy(update=overrides)


def _event() -> WebhookEventDoc:
    doc = WebhookEventDoc(
        event_id="evt_test",
        type="link.clicked",
        owner_id=ObjectId(),
        occurred_at=datetime(2026, 7, 22, tzinfo=timezone.utc),
        payload={"alias": "a", "link_id": "x"},
    )
    doc.id = ObjectId()
    return doc


def _make(endpoint: WebhookEndpointDoc | None, *, max_consecutive: int = 10):
    deliveries = AsyncMock()
    endpoints = AsyncMock()
    endpoints.find_by_id.return_value = endpoint
    endpoints.record_exhausted.return_value = 1
    events = AsyncMock()
    events.find_by_oid.return_value = _event()
    executor = DeliveryExecutor(
        deliveries,
        endpoints,
        events,
        default_renderers(),
        master_secret=_MASTER,
        max_consecutive_failures=max_consecutive,
    )
    return executor, deliveries, endpoints, events


def _post(status: int | None, error: str | None = None):
    return AsyncMock(return_value=PostResult(status, error, None))


class TestSuccessPath:
    @pytest.mark.asyncio
    async def test_delivers_with_valid_standard_webhooks_headers(self):
        endpoint = _endpoint()
        executor, deliveries, endpoints, _ = _make(endpoint)
        post = _post(204)
        with patch("services.webhooks.executor.post_public", post):
            await executor.attempt(_delivery())

        url, body = post.await_args[0]
        headers = post.await_args.kwargs["headers"]
        assert url == endpoint.url
        assert headers[HEADER_ID] == "msg_test"
        # The signature verifies against the raw secret — the whole point.
        assert verify(
            headers[HEADER_ID],
            int(headers[HEADER_TIMESTAMP]),
            body,
            _SECRET,
            headers[HEADER_SIGNATURE],
        )
        deliveries.record_attempt_and_finish.assert_awaited_once()
        assert (
            deliveries.record_attempt_and_finish.await_args[0][2]
            is DeliveryStatus.SUCCESS
        )
        endpoints.record_success.assert_awaited_once_with(endpoint.id)

    @pytest.mark.asyncio
    async def test_renders_once_and_freezes_body(self):
        executor, deliveries, _, _events = _make(_endpoint())
        with patch("services.webhooks.executor.post_public", _post(204)):
            await executor.attempt(_delivery())
        deliveries.set_rendered_body.assert_awaited_once()
        body = deliveries.set_rendered_body.await_args[0][1]
        assert '"type":"link.clicked"' in body

    @pytest.mark.asyncio
    async def test_prerendered_body_skips_event_read(self):
        """Retries resend the frozen body — the event row is not re-read."""
        executor, _, _, events = _make(_endpoint())
        row = _delivery(rendered_body='{"type":"link.clicked","data":{}}')
        with patch("services.webhooks.executor.post_public", _post(204)):
            await executor.attempt(row)
        events.find_by_oid.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_dropped_since_last_rides_the_payload(self):
        executor, deliveries, _, _ = _make(_endpoint())
        with patch("services.webhooks.executor.post_public", _post(204)):
            await executor.attempt(_delivery(dropped_since_last=42))
        body = deliveries.set_rendered_body.await_args[0][1]
        assert '"dropped_since_last":42' in body


class TestFailurePaths:
    @pytest.mark.asyncio
    async def test_failure_reschedules_per_ladder(self):
        executor, deliveries, _, _ = _make(_endpoint())
        before = datetime.now(timezone.utc)
        with patch("services.webhooks.executor.post_public", _post(500)):
            await executor.attempt(_delivery(attempt_count=1))
        next_at = deliveries.record_attempt_and_reschedule.await_args[0][2]
        # attempt 2 of the ladder → RETRY_SCHEDULE_SECONDS[2] = 300s
        assert next_at >= before + timedelta(seconds=RETRY_SCHEDULE_SECONDS[2] - 1)

    @pytest.mark.asyncio
    async def test_exhaustion_marks_failed_and_counts_streak(self):
        endpoint = _endpoint()
        executor, deliveries, endpoints, _ = _make(endpoint)
        last = len(RETRY_SCHEDULE_SECONDS) - 1
        with patch("services.webhooks.executor.post_public", _post(500)):
            await executor.attempt(_delivery(attempt_count=last))
        assert (
            deliveries.record_attempt_and_finish.await_args[0][2]
            is DeliveryStatus.FAILED
        )
        endpoints.record_exhausted.assert_awaited_once()
        endpoints.disable.assert_not_awaited()  # streak=1 < 10

    @pytest.mark.asyncio
    async def test_streak_at_threshold_disables(self):
        endpoint = _endpoint()
        executor, _, endpoints, _ = _make(endpoint, max_consecutive=3)
        endpoints.record_exhausted.return_value = 3
        last = len(RETRY_SCHEDULE_SECONDS) - 1
        with patch("services.webhooks.executor.post_public", _post(None, "boom")):
            await executor.attempt(_delivery(attempt_count=last))
        endpoints.disable.assert_awaited_once_with(
            endpoint.id, EndpointDisabledReason.CONSECUTIVE_FAILURES
        )

    @pytest.mark.asyncio
    async def test_410_disables_immediately(self):
        endpoint = _endpoint()
        executor, deliveries, endpoints, _ = _make(endpoint)
        with patch("services.webhooks.executor.post_public", _post(410)):
            await executor.attempt(_delivery())
        endpoints.disable.assert_awaited_once_with(
            endpoint.id, EndpointDisabledReason.GONE
        )
        assert (
            deliveries.record_attempt_and_finish.await_args[0][2]
            is DeliveryStatus.FAILED
        )

    @pytest.mark.asyncio
    async def test_disabled_endpoint_terminal(self):
        executor, deliveries, _, _ = _make(_endpoint(status=WebhookStatus.DISABLED))
        with patch("services.webhooks.executor.post_public", _post(204)) as post:
            await executor.attempt(_delivery())
        deliveries.mark_failed.assert_awaited_once()
        post.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_paused_endpoint_defers_instead_of_failing(self):
        """Paused is owner-controlled and temporary: the delivery waits."""
        executor, deliveries, _, _ = _make(_endpoint(status=WebhookStatus.PAUSED))
        with patch("services.webhooks.executor.post_public", _post(204)) as post:
            await executor.attempt(_delivery())
        deliveries.defer.assert_awaited_once()
        deliveries.mark_failed.assert_not_awaited()
        post.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_unreadable_secret_terminates_and_disables(self):
        """SECRET_KEY rotation must degrade loudly, never livelock: the row
        is terminally failed and the endpoint disabled with its own reason."""
        endpoint = _endpoint(signing_secret_enc="bm90LXJlYWwtY2lwaGVydGV4dA==")
        executor, deliveries, endpoints, _ = _make(endpoint)
        with patch("services.webhooks.executor.post_public", _post(204)) as post:
            await executor.attempt(_delivery())
        deliveries.mark_failed.assert_awaited_once()
        assert deliveries.mark_failed.await_args[0][1] == "secret_unreadable"
        endpoints.disable.assert_awaited_once_with(
            endpoint.id, EndpointDisabledReason.SECRET_UNREADABLE
        )
        post.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_failed_test_send_is_single_shot(self):
        """A failing TEST send records one attempt and stops: no reschedule,
        no exhaustion counting, no auto-disable — testing a broken endpoint
        must never mutate its real health."""
        endpoint = _endpoint()
        executor, deliveries, endpoints, _ = _make(endpoint)
        with patch("services.webhooks.executor.post_public", _post(500)):
            await executor.attempt(_delivery(is_test=True))
        assert (
            deliveries.record_attempt_and_finish.await_args[0][2]
            is DeliveryStatus.FAILED
        )
        deliveries.record_attempt_and_reschedule.assert_not_awaited()
        endpoints.record_exhausted.assert_not_awaited()
        endpoints.disable.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_passing_test_send_does_not_reset_streak(self):
        endpoint = _endpoint(consecutive_failures=7)
        executor, _, endpoints, _ = _make(endpoint)
        with patch("services.webhooks.executor.post_public", _post(204)):
            await executor.attempt(_delivery(is_test=True))
        endpoints.record_success.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_manual_retry_of_completed_row_is_single_shot(self):
        endpoint = _endpoint()
        executor, deliveries, endpoints, _ = _make(endpoint)
        row = _delivery(
            status=DeliveryStatus.FAILED,
            rendered_body='{"type":"link.clicked","data":{}}',
        )
        with patch("services.webhooks.executor.post_public", _post(410)):
            await executor.attempt(row)
        endpoints.disable.assert_not_awaited()
        deliveries.record_attempt_and_reschedule.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_event_ttl_race_terminal_not_crash(self):
        executor, deliveries, _, events = _make(_endpoint())
        events.find_by_oid.return_value = None
        with patch("services.webhooks.executor.post_public", _post(204)) as post:
            await executor.attempt(_delivery())
        deliveries.mark_failed.assert_awaited_once()
        assert deliveries.mark_failed.await_args[0][1] == "event_expired"
        post.assert_not_awaited()


class TestPendingSlotRelease:
    """Every terminal outcome releases the endpoint's pending slot exactly
    once; non-terminal outcomes and rows that never reserved one do not."""

    @pytest.mark.asyncio
    async def test_success_releases(self):
        endpoint = _endpoint()
        executor, deliveries, endpoints, _ = _make(endpoint)
        deliveries.record_attempt_and_finish.return_value = True
        with patch("services.webhooks.executor.post_public", _post(204)):
            await executor.attempt(_delivery(endpoint_id=endpoint.id))
        endpoints.release_pending.assert_awaited_once_with(endpoint.id)

    @pytest.mark.asyncio
    async def test_exhaustion_releases(self):
        endpoint = _endpoint()
        executor, deliveries, endpoints, _ = _make(endpoint)
        deliveries.record_attempt_and_finish.return_value = True
        last = len(RETRY_SCHEDULE_SECONDS) - 1
        with patch("services.webhooks.executor.post_public", _post(500)):
            await executor.attempt(
                _delivery(endpoint_id=endpoint.id, attempt_count=last)
            )
        endpoints.release_pending.assert_awaited_once_with(endpoint.id)

    @pytest.mark.asyncio
    async def test_terminal_without_attempt_releases(self):
        endpoint = _endpoint(status=WebhookStatus.DISABLED)
        executor, deliveries, endpoints, _ = _make(endpoint)
        deliveries.mark_failed.return_value = True
        await executor.attempt(_delivery(endpoint_id=endpoint.id))
        endpoints.release_pending.assert_awaited_once_with(endpoint.id)

    @pytest.mark.asyncio
    async def test_reschedule_and_defer_keep_the_slot(self):
        executor, _, endpoints, _ = _make(_endpoint())
        with patch("services.webhooks.executor.post_public", _post(500)):
            await executor.attempt(_delivery())
        with patch("services.webhooks.executor.post_public", _post(429)):
            await executor.attempt(_delivery())
        endpoints.release_pending.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_test_send_never_releases(self):
        executor, deliveries, endpoints, _ = _make(_endpoint())
        deliveries.record_attempt_and_finish.return_value = True
        with patch("services.webhooks.executor.post_public", _post(204)):
            await executor.attempt(_delivery(is_test=True))
        endpoints.release_pending.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_manual_retry_of_finished_row_never_releases(self):
        executor, deliveries, endpoints, _ = _make(_endpoint())
        deliveries.record_attempt_and_finish.return_value = False
        row = _delivery(status=DeliveryStatus.FAILED, rendered_body="{}")
        with patch("services.webhooks.executor.post_public", _post(204)):
            await executor.attempt(row)
        endpoints.release_pending.assert_not_awaited()


class TestRotationGrace:
    @pytest.mark.asyncio
    async def test_success_after_grace_secret_sends_dual_signatures(self):
        old_secret = "whsec_b2xkLXNlY3JldC1vbGQtc2VjcmV0"
        endpoint = _endpoint(
            previous_secret_enc=encrypt_secret(
                old_secret, _MASTER, domain=SECRET_ENC_DOMAIN
            ),
            previous_secret_expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        )
        executor, _, _, _ = _make(endpoint)
        post = _post(204)
        with patch("services.webhooks.executor.post_public", post):
            await executor.attempt(_delivery())
        headers = post.await_args.kwargs["headers"]
        _, body = post.await_args[0]
        ts = int(headers[HEADER_TIMESTAMP])
        assert verify("msg_test", ts, body, _SECRET, headers[HEADER_SIGNATURE])
        assert verify("msg_test", ts, body, old_secret, headers[HEADER_SIGNATURE])


class TestRateLimit:
    """429 is receiver flow control: defer without burning the ladder."""

    def _post_429(self, retry_after: float | None):
        return AsyncMock(return_value=PostResult(429, None, None, retry_after))

    @pytest.mark.asyncio
    async def test_429_defers_without_ladder_or_streak(self):
        executor, deliveries, endpoints, _ = _make(_endpoint())
        with patch("services.webhooks.executor.post_public", self._post_429(None)):
            await executor.attempt(_delivery(attempt_count=1))
        deliveries.defer.assert_awaited_once()
        assert (
            deliveries.defer.await_args.kwargs["delay_seconds"]
            == RATE_LIMIT_FALLBACK_SECONDS
        )
        deliveries.record_attempt_and_reschedule.assert_not_awaited()
        deliveries.record_attempt_and_finish.assert_not_awaited()
        endpoints.record_exhausted.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_429_honors_retry_after(self):
        executor, deliveries, _, _ = _make(_endpoint())
        with patch("services.webhooks.executor.post_public", self._post_429(5.0)):
            await executor.attempt(_delivery())
        assert deliveries.defer.await_args.kwargs["delay_seconds"] == 5

    @pytest.mark.asyncio
    async def test_429_retry_after_is_capped(self):
        executor, deliveries, _, _ = _make(_endpoint())
        with patch("services.webhooks.executor.post_public", self._post_429(3600.0)):
            await executor.attempt(_delivery())
        assert (
            deliveries.defer.await_args.kwargs["delay_seconds"]
            == RATE_LIMIT_MAX_DEFER_SECONDS
        )

    @pytest.mark.asyncio
    async def test_single_shot_429_is_terminal_not_deferred(self):
        # A rate-limited test send must report its outcome synchronously,
        # not silently park the row.
        executor, deliveries, _, _ = _make(_endpoint())
        with patch("services.webhooks.executor.post_public", self._post_429(5.0)):
            await executor.attempt(_delivery(is_test=True, next_attempt_at=None))
        deliveries.defer.assert_not_awaited()
        assert (
            deliveries.record_attempt_and_finish.await_args[0][2]
            is DeliveryStatus.FAILED
        )


class TestDeliveryUrl:
    @pytest.mark.asyncio
    async def test_discord_flavor_appends_components_param(self):
        endpoint = _endpoint(flavor=WebhookFlavor.DISCORD)
        executor, _, _, _ = _make(endpoint)
        post = _post(204)
        with patch("services.webhooks.executor.post_public", post):
            await executor.attempt(_delivery())
        url = post.await_args[0][0]
        assert url == f"{endpoint.url}?with_components=true"

    @pytest.mark.asyncio
    async def test_raw_flavor_url_is_untouched(self):
        endpoint = _endpoint()
        executor, _, _, _ = _make(endpoint)
        post = _post(204)
        with patch("services.webhooks.executor.post_public", post):
            await executor.attempt(_delivery())
        assert post.await_args[0][0] == endpoint.url


class TestRenderFailures:
    @pytest.mark.asyncio
    async def test_unknown_flavor_is_terminal(self):
        endpoint = _endpoint()
        deliveries, endpoints, events = AsyncMock(), AsyncMock(), AsyncMock()
        endpoints.find_by_id.return_value = endpoint
        events.find_by_oid.return_value = _event()
        deliveries.mark_failed.return_value = True
        executor = DeliveryExecutor(
            deliveries, endpoints, events, {}, master_secret=_MASTER
        )
        with patch("services.webhooks.executor.post_public", _post(204)) as post:
            await executor.attempt(_delivery(endpoint_id=endpoint.id))
        assert deliveries.mark_failed.await_args[0][1].startswith("unknown_flavor:")
        endpoints.release_pending.assert_awaited_once_with(endpoint.id)
        post.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_payload_over_cap_is_terminal(self):
        endpoint = _endpoint()
        deliveries, endpoints, events = AsyncMock(), AsyncMock(), AsyncMock()
        endpoints.find_by_id.return_value = endpoint
        events.find_by_oid.return_value = _event()
        deliveries.mark_failed.return_value = True
        executor = DeliveryExecutor(
            deliveries,
            endpoints,
            events,
            default_renderers(),
            master_secret=_MASTER,
            max_payload_bytes=16,
        )
        with patch("services.webhooks.executor.post_public", _post(204)) as post:
            await executor.attempt(_delivery(endpoint_id=endpoint.id))
        assert deliveries.mark_failed.await_args[0][1] == "payload_over_cap"
        endpoints.release_pending.assert_awaited_once_with(endpoint.id)
        post.assert_not_awaited()
