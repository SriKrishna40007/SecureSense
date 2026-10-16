"""Tests for network-event JSON validation."""

import json
from datetime import UTC, datetime

import pytest

from securesense.domain.policies.models import Protocol
from securesense.infrastructure.mqtt.network_event_adapter import (
    NetworkEventValidationError,
    parse_network_event,
)


def valid_payload() -> dict[str, object]:
    return {
        "device_id": "TEMP-001",
        "source_ip": "192.0.2.10",
        "destination": "mqtt-gateway",
        "destination_ip": "192.0.2.20",
        "protocol": "mqtt",
        "destination_port": 8883,
        "network_zone": "iot",
        "timestamp": "2026-10-10T08:00:00+00:00",
    }


def test_parses_explicit_network_event() -> None:
    event = parse_network_event(json.dumps(valid_payload()))

    assert event.device_id == "TEMP-001"
    assert event.source_ip == "192.0.2.10"
    assert event.destination == "mqtt-gateway"
    assert event.destination_ip == "192.0.2.20"
    assert event.protocol is Protocol.MQTT
    assert event.destination_port == 8883
    assert event.network_zone == "iot"
    assert event.timestamp == datetime(2026, 10, 10, 8, 0, tzinfo=UTC)


@pytest.mark.parametrize(
    "payload",
    [
        b"not-json",
        b"[]",
        b"{}",
        b'{"device_id":"TEMP-001"}',
    ],
)
def test_rejects_malformed_or_incomplete_payload(payload: bytes) -> None:
    with pytest.raises(NetworkEventValidationError):
        parse_network_event(payload)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("source_ip", "not-an-ip"),
        ("destination_ip", "300.1.1.1"),
        ("destination_port", True),
        ("destination_port", 0),
        ("destination_port", 65536),
        ("protocol", "icmp"),
        ("timestamp", "not-a-timestamp"),
        ("timestamp", "2026-10-10T08:00:00"),
    ],
)
def test_rejects_invalid_network_fields(field: str, value: object) -> None:
    payload = valid_payload()
    payload[field] = value

    with pytest.raises(NetworkEventValidationError):
        parse_network_event(json.dumps(payload))


def test_rejects_oversized_payload() -> None:
    with pytest.raises(NetworkEventValidationError, match="exceeds"):
        parse_network_event(b" " * 65_537)
