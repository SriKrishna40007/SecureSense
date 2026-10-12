from datetime import UTC, datetime

from securesense.domain.telemetry.sensor_reading import SensorReading


def test_sensor_reading_stores_temperature() -> None:
    timestamp = datetime.now(UTC)

    reading = SensorReading(
        device_id="TEMP-001",
        metric="temperature",
        value=72.4,
        unit="celsius",
        timestamp=timestamp,
    )

    assert reading.device_id == "TEMP-001"
    assert reading.metric == "temperature"
    assert reading.value == 72.4
    assert reading.unit == "celsius"
    assert reading.timestamp == timestamp


def test_sensor_reading_stores_vibration() -> None:
    timestamp = datetime.now(UTC)

    reading = SensorReading(
        device_id="VIB-001",
        metric="vibration",
        value=0.18,
        unit="g",
        timestamp=timestamp,
    )

    assert reading.device_id == "VIB-001"
    assert reading.metric == "vibration"
    assert reading.value == 0.18
    assert reading.unit == "g"


def test_sensor_reading_stores_pressure() -> None:
    timestamp = datetime.now(UTC)

    reading = SensorReading(
        device_id="PRESS-001",
        metric="pressure",
        value=4.2,
        unit="bar",
        timestamp=timestamp,
    )

    assert reading.device_id == "PRESS-001"
    assert reading.metric == "pressure"
    assert reading.value == 4.2
    assert reading.unit == "bar"
