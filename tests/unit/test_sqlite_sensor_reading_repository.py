from datetime import UTC, datetime, timedelta

import pytest

from securesense.domain.telemetry.sensor_reading import SensorReading
from securesense.infrastructure.persistence.sqlite_sensor_reading_repository import (
    SQLiteSensorReadingRepository,
)


def reading(
    value: float = 72.4,
    *,
    device_id: str = "TEMP-001",
    metric: str = "temperature",
    timestamp: datetime | None = None,
) -> SensorReading:
    return SensorReading(
        device_id=device_id,
        metric=metric,
        value=value,
        unit="celsius",
        timestamp=timestamp or datetime.now(UTC),
    )


def test_saved_reading_survives_repository_recreation(tmp_path):
    database = tmp_path / "telemetry.sqlite3"
    first = SQLiteSensorReadingRepository(database)
    saved = first.save(reading())

    second = SQLiteSensorReadingRepository(database)
    results = second.list_recent()

    assert len(results) == 1
    assert results[0]["reading_id"] == saved["reading_id"]
    assert results[0]["device_id"] == "TEMP-001"
    assert results[0]["metric"] == "temperature"
    assert results[0]["value"] == pytest.approx(72.4)


def test_latest_by_device_returns_latest_reading_per_metric(tmp_path):
    repository = SQLiteSensorReadingRepository(tmp_path / "telemetry.sqlite3")
    base = datetime.now(UTC)

    repository.save(reading(70.0, timestamp=base))
    repository.save(reading(74.5, timestamp=base + timedelta(seconds=1)))
    repository.save(
        reading(
            2.1,
            metric="vibration",
            timestamp=base + timedelta(seconds=2),
        )
    )

    latest = repository.latest_by_device()

    assert len(latest) == 2
    by_metric = {item["metric"]: item["value"] for item in latest}
    assert by_metric["temperature"] == pytest.approx(74.5)
    assert by_metric["vibration"] == pytest.approx(2.1)


def test_history_is_bounded(tmp_path):
    repository = SQLiteSensorReadingRepository(
        tmp_path / "telemetry.sqlite3",
        max_history=2,
    )

    for value in (70.0, 71.0, 72.0):
        repository.save(reading(value))

    results = repository.list_recent()

    assert len(results) == 2
    assert [item["value"] for item in results] == [72.0, 71.0]


@pytest.mark.parametrize(
    "invalid",
    [
        reading(float("nan")),
        reading(float("inf")),
        reading(float("-inf")),
        reading(timestamp=datetime.fromisoformat('2026-01-01T00:00:00')),
    ],
)
def test_invalid_readings_are_rejected(tmp_path, invalid):
    repository = SQLiteSensorReadingRepository(tmp_path / "telemetry.sqlite3")

    with pytest.raises(ValueError):
        repository.save(invalid)


def test_empty_device_id_is_rejected(tmp_path):
    repository = SQLiteSensorReadingRepository(tmp_path / "telemetry.sqlite3")

    with pytest.raises(ValueError, match="device_id"):
        repository.save(reading(device_id="  "))


def test_history_limit_must_be_positive(tmp_path):
    with pytest.raises(ValueError, match="max_history"):
        SQLiteSensorReadingRepository(tmp_path / "telemetry.sqlite3", max_history=0)
