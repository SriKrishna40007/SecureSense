"""Convert incoming MQTT telemetry messages into domain objects."""

import json
from datetime import UTC, datetime
from math import isfinite
from typing import Any

from securesense.domain.telemetry.sensor_reading import SensorReading


class TelemetryValidationError(ValueError):
    """Raised when an MQTT telemetry message is invalid."""


def parse_sensor_reading(payload: str | bytes) -> SensorReading:
    """Parse and validate a JSON sensor payload."""

    try:
        data: Any = json.loads(payload)
    except (json.JSONDecodeError, UnicodeDecodeError, TypeError) as exc:
        raise TelemetryValidationError("Payload must contain valid JSON") from exc

    if not isinstance(data, dict):
        raise TelemetryValidationError("Payload must be a JSON object")

    required_fields = {"device_id", "metric", "value", "unit"}
    missing_fields = required_fields - data.keys()
    if missing_fields:
        raise TelemetryValidationError(
            f"Missing required fields: {', '.join(sorted(missing_fields))}"
        )

    for field in ("device_id", "metric", "unit"):
        if not isinstance(data[field], str) or not data[field].strip():
            raise TelemetryValidationError(
                f"'{field}' must be a non-empty string"
            )

    value = data["value"]
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TelemetryValidationError("'value' must be a number")

    numeric_value = float(value)
    if not isfinite(numeric_value):
        raise TelemetryValidationError("'value' must be finite")

    timestamp_value = data.get("timestamp")
    if timestamp_value is None:
        timestamp = datetime.now(UTC)
    elif isinstance(timestamp_value, str):
        try:
            timestamp = datetime.fromisoformat(timestamp_value)
        except ValueError as exc:
            raise TelemetryValidationError(
                "'timestamp' must be a valid ISO 8601 timestamp"
            ) from exc

        if timestamp.tzinfo is None:
            raise TelemetryValidationError(
                "'timestamp' must include a timezone"
            )
    else:
        raise TelemetryValidationError(
            "'timestamp' must be an ISO 8601 string"
        )

    return SensorReading(
        device_id=data["device_id"].strip(),
        metric=data["metric"].strip(),
        value=numeric_value,
        unit=data["unit"].strip(),
        timestamp=timestamp,
    )
