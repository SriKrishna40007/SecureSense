"""SQLite persistence for validated IoT sensor readings."""

import math
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any

from securesense.domain.telemetry.sensor_reading import SensorReading
from securesense.infrastructure.persistence.sqlite_schema import (
    mark_schema_current,
    validate_schema_version,
)


class SQLiteSensorReadingRepository:
    """Store bounded sensor history in the shared SecureSense database."""

    def __init__(
        self,
        database_path: Path | str,
        max_history: int = 5000,
    ) -> None:
        if isinstance(max_history, bool) or not isinstance(max_history, int):
            raise TypeError("'max_history' must be an integer")
        if max_history < 1:
            raise ValueError("'max_history' must be at least 1")

        self._database_path = str(database_path)
        self._max_history = max_history

        if self._database_path != ":memory:":
            Path(self._database_path).parent.mkdir(
                parents=True,
                exist_ok=True,
            )

        with self._connect() as connection:
            validate_schema_version(connection)
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS sensor_readings (
                    reading_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_id TEXT NOT NULL,
                    metric TEXT NOT NULL,
                    value REAL NOT NULL,
                    unit TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    received_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    CHECK (length(trim(device_id)) > 0),
                    CHECK (length(trim(metric)) > 0),
                    CHECK (length(trim(unit)) > 0)
                )
                """
            )
            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_sensor_readings_device_metric
                ON sensor_readings (device_id, metric, reading_id DESC)
                """
            )
            mark_schema_current(connection)

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        """Open a database connection and always close it."""
        connection = sqlite3.connect(self._database_path, timeout=10.0)
        connection.row_factory = sqlite3.Row
        try:
            yield connection
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    @staticmethod
    def _validate_reading(reading: SensorReading) -> str:
        if not isinstance(reading, SensorReading):
            raise TypeError("'reading' must be a SensorReading")

        for field in ("device_id", "metric", "unit"):
            value = getattr(reading, field)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"'{field}' must not be empty")

        if (
            isinstance(reading.value, bool)
            or not isinstance(reading.value, (int, float))
            or not math.isfinite(reading.value)
        ):
            raise ValueError("'value' must be a finite number")

        if not isinstance(reading.timestamp, datetime):
            raise TypeError("'timestamp' must be a datetime")
        if (
            reading.timestamp.tzinfo is None
            or reading.timestamp.utcoffset() is None
        ):
            raise ValueError("'timestamp' must include a timezone")

        return reading.timestamp.isoformat()

    @staticmethod
    def _as_dict(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "reading_id": row["reading_id"],
            "device_id": row["device_id"],
            "metric": row["metric"],
            "value": row["value"],
            "unit": row["unit"],
            "timestamp": row["timestamp"],
            "received_at": row["received_at"],
        }

    def save(self, reading: SensorReading) -> dict[str, Any]:
        """Persist one reading and prune the oldest rows beyond the limit."""
        timestamp = self._validate_reading(reading)

        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                """
                INSERT INTO sensor_readings (
                    device_id, metric, value, unit, timestamp
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    reading.device_id.strip(),
                    reading.metric.strip(),
                    float(reading.value),
                    reading.unit.strip(),
                    timestamp,
                ),
            )
            reading_id = cursor.lastrowid
            connection.execute(
                """
                DELETE FROM sensor_readings
                WHERE reading_id NOT IN (
                    SELECT reading_id
                    FROM sensor_readings
                    ORDER BY reading_id DESC
                    LIMIT ?
                )
                """,
                (self._max_history,),
            )
            row = connection.execute(
                "SELECT * FROM sensor_readings WHERE reading_id = ?",
                (reading_id,),
            ).fetchone()

        if row is None:
            raise RuntimeError("Saved sensor reading could not be retrieved")
        return self._as_dict(row)

    def list_recent(self, limit: int | None = None) -> list[dict[str, Any]]:
        """Return newest readings first, defaulting to the retention limit."""
        if limit is None:
            limit = min(100, self._max_history)
        if isinstance(limit, bool) or not isinstance(limit, int):
            raise TypeError("'limit' must be an integer")
        if not 1 <= limit <= self._max_history:
            raise ValueError(
                f"'limit' must be between 1 and {self._max_history}"
            )

        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT * FROM sensor_readings
                ORDER BY reading_id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()

        return [self._as_dict(row) for row in rows]

    def latest_by_device(self) -> list[dict[str, Any]]:
        """Return the latest stored reading for each device and metric."""
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT reading_id, device_id, metric, value, unit,
                       timestamp, received_at
                FROM (
                    SELECT *,
                           ROW_NUMBER() OVER (
                               PARTITION BY device_id, metric
                               ORDER BY reading_id DESC
                           ) AS reading_rank
                    FROM sensor_readings
                )
                WHERE reading_rank = 1
                ORDER BY device_id, metric
                """
            ).fetchall()

        return [self._as_dict(row) for row in rows]
