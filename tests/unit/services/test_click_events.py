"""Tests for the ClickEvent DTO and its stream wire format."""

from __future__ import annotations

import pytest
from pydantic import ValidationError as PydanticValidationError

from infrastructure.cache.url_cache import UrlCacheData
from services.click.events import (
    EVENT_TYPE_CLICK,
    STREAM_FIELD_DATA,
    STREAM_FIELD_TYPE,
    STREAM_FIELD_VERSION,
    ClickEvent,
    click_event_from_payload,
    from_stream_fields,
    to_stream_fields,
)


def make_url_data(**overrides) -> UrlCacheData:
    base = dict(
        _id="65f000000000000000000001",
        alias="abc",
        long_url="https://example.com",
        block_bots=False,
        password_hash=None,
        expiration_time=None,
        max_clicks=None,
        url_status="ACTIVE",
        schema_version="v2",
        owner_id=None,
        total_clicks=0,
        domain="spoo.me",
    )
    base.update(overrides)
    return UrlCacheData(**base)


def make_event(**overrides) -> ClickEvent:
    base = dict(
        short_code="abc",
        schema_key="v2",
        is_emoji=False,
        url=make_url_data(),
        client_ip="1.2.3.4",
        user_agent="Mozilla/5.0",
        referrer="https://t.co/x",
        cf_city="Berlin",
        redirect_ms=7,
    )
    base.update(overrides)
    return ClickEvent(**base)


class TestClickEvent:
    def test_event_is_frozen(self):
        event = make_event()
        with pytest.raises(PydanticValidationError):
            event.redirect_ms = 99  # type: ignore[misc]

    def test_enqueued_at_defaults_to_now_utc(self):
        event = make_event()
        assert event.enqueued_at.tzinfo is not None

    def test_url_snapshot_preserves_nested_model(self):
        event = make_event(url=make_url_data(domain="", schema_version="v1"))
        assert isinstance(event.url, UrlCacheData)
        assert event.url.schema_version == "v1"


class TestWireFormat:
    def test_round_trip_through_stream_fields(self):
        event = make_event()
        fields = to_stream_fields(event)

        assert fields[STREAM_FIELD_TYPE] == EVENT_TYPE_CLICK
        assert fields[STREAM_FIELD_VERSION] == "1"
        assert STREAM_FIELD_DATA in fields

        restored = from_stream_fields(fields)
        assert restored == event

    def test_wire_fields_are_flat_strings(self):
        """XADD requires flat str/bytes field values."""
        fields = to_stream_fields(make_event())
        for key, value in fields.items():
            assert isinstance(key, str)
            assert isinstance(value, str)

    def test_from_stream_fields_returns_none_on_malformed_json(self):
        assert from_stream_fields({STREAM_FIELD_DATA: "{not json"}) is None

    def test_from_stream_fields_returns_none_on_missing_data_field(self):
        assert from_stream_fields({"other": "x"}) is None

    def test_from_stream_fields_returns_none_on_schema_mismatch(self):
        assert from_stream_fields({STREAM_FIELD_DATA: '{"short_code": "abc"}'}) is None


class TestPayloadDecode:
    """The FastStream path: handlers receive the decoded __data__ payload."""

    def test_decodes_dict_payload(self):
        event = make_event()
        payload = event.model_dump(mode="json")
        restored = click_event_from_payload(payload)
        assert restored == event

    def test_returns_none_on_non_dict_payload(self):
        assert click_event_from_payload("raw string") is None
        assert click_event_from_payload(None) is None
        assert click_event_from_payload([1, 2]) is None

    def test_returns_none_on_invalid_fields(self):
        assert click_event_from_payload({"short_code": "abc"}) is None

    def test_tolerates_unknown_extra_fields(self):
        """Forward compat: a newer producer may add fields."""
        payload = make_event().model_dump(mode="json")
        payload["future_field"] = "whatever"
        restored = click_event_from_payload(payload)
        assert restored is not None
        assert restored.short_code == "abc"
