import json
from datetime import UTC, datetime

import pytest

from securesense.domain.telemetry.sensor_reading import SensorReading
from securesense.infrastructure.mqtt.telemetry_adapter import (
    TelemetryValidationError,
    parse_sensor_reading,
)


def test_parses_valid_sensor_reading():
    payload = json.dumps(
        {
            "device_id": "TEMP-001",
            "metric": "temperature",
            "value": 24.0,
            "unit": "celsius",
            "timestamp": "2026-10-10T06:00:00+00:00",
        }
    )

    reading = parse_sensor_reading(payload)

    assert reading == SensorReading(
        device_id="TEMP-001",
        metric="temperature",
        value=24.0,
        unit="celsius",
        timestamp=datetime(2026, 10, 10, 6, 0, tzinfo=UTC),
    )


def test_accepts_bytes_payload():
    payload = (
        b'{"device_id":"TEMP-001","metric":"temperature",'
        b'"value":24,"unit":"celsius"}'
    )

    reading = parse_sensor_reading(payload)

    assert reading.device_id == "TEMP-001"
    assert reading.value == 24.0
    assert reading.timestamp.tzinfo is not None


@pytest.mark.parametrize(
    "payload",
    [
        "not-json",
        "[]",
        "{}",
        (
            '{"device_id":"TEMP-001","metric":"temperature",'
            '"value":24,"unit":"celsius","timestamp":"not-a-date"}'
        ),
    ],
)
def test_rejects_invalid_payloads(payload):
    with pytest.raises(TelemetryValidationError):
        parse_sensor_reading(payload)


@pytest.mark.parametrize("value", [True, float("inf"), float("-inf"), float("nan"), "24"])
def test_rejects_invalid_sensor_values(value):
    payload = json.dumps(
        {
            "device_id": "TEMP-001",
            "metric": "temperature",
            "value": value,
            "unit": "celsius",
        }
    )

    with pytest.raises(TelemetryValidationError):
        parse_sensor_reading(payload)


def test_rejects_empty_device_id():
    payload = json.dumps(
        {
            "device_id": " ",
            "metric": "temperature",
            "value": 24.0,
            "unit": "celsius",
        }
    )

    with pytest.raises(TelemetryValidationError):
        parse_sensor_reading(payload)


def test_rejects_timestamp_without_timezone():
    payload = json.dumps(
        {
            "device_id": "TEMP-001",
            "metric": "temperature",
            "value": 24.0,
            "unit": "celsius",
            "timestamp": "2026-10-10T06:00:00",
        }
    )

    with pytest.raises(TelemetryValidationError):
        parse_sensor_reading(payload)
