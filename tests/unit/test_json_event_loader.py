import json
from datetime import UTC, datetime

import pytest

from securesense.domain.policies.models import Protocol
from securesense.infrastructure.events.json_event_loader import JsonEventLoader


def valid_record() -> dict[str, object]:
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


def write_payload(tmp_path, payload: object):
    path = tmp_path / "events.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_loads_network_events_from_json(tmp_path) -> None:
    path = write_payload(tmp_path, {"events": [valid_record()]})

    events = JsonEventLoader().load(path)

    assert len(events) == 1
    assert events[0].device_id == "TEMP-001"
    assert events[0].protocol is Protocol.MQTT
    assert events[0].destination_port == 8883
    assert events[0].timestamp == datetime(2026, 10, 10, 8, 0, tzinfo=UTC)


def test_accepts_iso_timestamp_ending_in_z(tmp_path) -> None:
    record = valid_record()
    record["timestamp"] = "2026-10-10T08:00:00Z"
    path = write_payload(tmp_path, {"events": [record]})

    event = JsonEventLoader().load(path)[0]

    assert event.timestamp.utcoffset() == UTC.utcoffset(event.timestamp)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("destination_port", True, "must be an integer"),
        ("destination_port", 0, "between 1 and 65535"),
        ("protocol", "icmp", "protocol is unsupported"),
        ("timestamp", "not-a-date", "valid ISO 8601"),
        ("timestamp", "2026-10-10T08:00:00", "must include a timezone"),
        ("device_id", " ", "must be a non-empty string"),
    ],
)
def test_rejects_invalid_event_fields(
    tmp_path, field: str, value: object, message: str
) -> None:
    record = valid_record()
    record[field] = value
    path = write_payload(tmp_path, {"events": [record]})

    with pytest.raises((ValueError, TypeError), match=message):
        JsonEventLoader().load(path)


def test_rejects_missing_events_array(tmp_path) -> None:
    path = write_payload(tmp_path, {"items": []})

    with pytest.raises(TypeError, match="'events' must be a JSON array"):
        JsonEventLoader().load(path)


def test_rejects_missing_required_field(tmp_path) -> None:
    record = valid_record()
    del record["device_id"]
    path = write_payload(tmp_path, {"events": [record]})

    with pytest.raises(ValueError, match="missing required fields"):
        JsonEventLoader().load(path)


def test_rejects_malformed_json(tmp_path) -> None:
    path = tmp_path / "broken.json"
    path.write_text('{"events": [', encoding="utf-8")

    with pytest.raises(ValueError, match="Invalid JSON"):
        JsonEventLoader().load(path)
