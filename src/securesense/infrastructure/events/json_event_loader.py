"""Load and validate network events from JSON files."""

import json
from collections.abc import Mapping
from datetime import datetime
from pathlib import Path
from typing import Any, ClassVar

from securesense.domain.policies.models import Protocol
from securesense.domain.telemetry.models import NetworkEvent


class JsonEventLoader:
    """Convert validated JSON event records into NetworkEvent objects."""

    _REQUIRED_FIELDS: ClassVar[frozenset[str]] = frozenset(
        {
            "device_id",
            "source_ip",
            "destination",
            "destination_ip",
            "protocol",
            "destination_port",
            "network_zone",
            "timestamp",
        }
    )

    def load(self, file_path: str | Path) -> tuple[NetworkEvent, ...]:
        """Load events from a JSON file with an ``events`` array."""
        path = Path(file_path)

        try:
            with path.open("r", encoding="utf-8") as file:
                payload: Any = json.load(file)
        except OSError as exc:
            raise ValueError(
                f"Cannot read event file '{path}': {exc}"
            ) from exc
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"Invalid JSON in event file '{path}': {exc.msg}"
            ) from exc

        if not isinstance(payload, dict):
            raise TypeError("Event file root must be a JSON object")

        records = payload.get("events")
        if not isinstance(records, list):
            raise TypeError("'events' must be a JSON array")

        events: list[NetworkEvent] = []

        for index, record in enumerate(records):
            label = f"events[{index}]"

            if not isinstance(record, Mapping):
                raise TypeError(f"{label} must be a JSON object")

            missing = self._REQUIRED_FIELDS - record.keys()
            if missing:
                raise ValueError(
                    f"{label} is missing required fields: "
                    f"{', '.join(sorted(missing))}"
                )

            text_fields = (
                "device_id",
                "source_ip",
                "destination",
                "destination_ip",
                "network_zone",
                "timestamp",
                "protocol",
            )
            for field in text_fields:
                value = record[field]
                if not isinstance(value, str) or not value.strip():
                    raise ValueError(
                        f"{label}.{field} must be a non-empty string"
                    )

            port = record["destination_port"]
            if isinstance(port, bool) or not isinstance(port, int):
                raise TypeError(
                    f"{label}.destination_port must be an integer"
                )
            if not 1 <= port <= 65535:
                raise ValueError(
                    f"{label}.destination_port must be between 1 and 65535"
                )

            try:
                protocol = Protocol(record["protocol"].lower())
            except ValueError as exc:
                allowed = ", ".join(item.value for item in Protocol)
                raise ValueError(
                    f"{label}.protocol is unsupported; use one of: {allowed}"
                ) from exc

            try:
                timestamp = datetime.fromisoformat(record["timestamp"])
            except ValueError as exc:
                raise ValueError(
                    f"{label}.timestamp must be a valid ISO 8601 timestamp"
                ) from exc

            if timestamp.tzinfo is None or timestamp.utcoffset() is None:
                raise ValueError(
                    f"{label}.timestamp must include a timezone offset"
                )

            events.append(
                NetworkEvent(
                    device_id=record["device_id"].strip(),
                    source_ip=record["source_ip"].strip(),
                    destination=record["destination"].strip(),
                    destination_ip=record["destination_ip"].strip(),
                    protocol=protocol,
                    destination_port=port,
                    network_zone=record["network_zone"].strip(),
                    timestamp=timestamp,
                )
            )

        return tuple(events)
