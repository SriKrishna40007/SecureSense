"""Parse and validate explicit network-security events from JSON."""

import ipaddress
import json
from datetime import datetime
from typing import Any

from securesense.domain.policies.models import Protocol
from securesense.domain.telemetry.models import NetworkEvent


MAX_NETWORK_EVENT_BYTES = 65_536


class NetworkEventValidationError(ValueError):
    """Raised when an incoming network event is invalid."""


def parse_network_event(payload: str | bytes) -> NetworkEvent:
    """Convert one JSON network-event object into a validated domain event."""
    if isinstance(payload, bytes):
        if len(payload) > MAX_NETWORK_EVENT_BYTES:
            raise NetworkEventValidationError("Payload exceeds 65536 bytes")
    elif isinstance(payload, str):
        if len(payload.encode("utf-8")) > MAX_NETWORK_EVENT_BYTES:
            raise NetworkEventValidationError("Payload exceeds 65536 bytes")
    else:
        raise NetworkEventValidationError("Payload must be text or bytes")

    try:
        data: Any = json.loads(payload)
    except (json.JSONDecodeError, UnicodeDecodeError, TypeError) as exc:
        raise NetworkEventValidationError("Payload must contain valid JSON") from exc

    if not isinstance(data, dict):
        raise NetworkEventValidationError("Payload must be a JSON object")

    required = {
        "device_id",
        "source_ip",
        "destination",
        "destination_ip",
        "protocol",
        "destination_port",
        "network_zone",
        "timestamp",
    }
    missing = required - data.keys()
    if missing:
        raise NetworkEventValidationError(
            f"Missing required fields: {', '.join(sorted(missing))}"
        )

    text_fields = (
        "device_id",
        "source_ip",
        "destination",
        "destination_ip",
        "protocol",
        "network_zone",
        "timestamp",
    )
    for field in text_fields:
        value = data[field]
        if not isinstance(value, str) or not value.strip():
            raise NetworkEventValidationError(f"'{field}' must be a non-empty string")

    for field in ("source_ip", "destination_ip"):
        try:
            ipaddress.ip_address(data[field].strip())
        except ValueError as exc:
            raise NetworkEventValidationError(
                f"'{field}' must be a valid IP address"
            ) from exc

    port = data["destination_port"]
    if isinstance(port, bool) or not isinstance(port, int):
        raise NetworkEventValidationError("'destination_port' must be an integer")
    if not 1 <= port <= 65535:
        raise NetworkEventValidationError(
            "'destination_port' must be between 1 and 65535"
        )

    try:
        protocol = Protocol(data["protocol"].strip().lower())
    except ValueError as exc:
        allowed = ", ".join(item.value for item in Protocol)
        raise NetworkEventValidationError(
            f"'protocol' must be one of: {allowed}"
        ) from exc

    try:
        timestamp = datetime.fromisoformat(data["timestamp"].strip())
    except ValueError as exc:
        raise NetworkEventValidationError(
            "'timestamp' must be a valid ISO 8601 timestamp"
        ) from exc

    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise NetworkEventValidationError("'timestamp' must include a timezone")

    return NetworkEvent(
        device_id=data["device_id"].strip(),
        source_ip=data["source_ip"].strip(),
        destination=data["destination"].strip(),
        destination_ip=data["destination_ip"].strip(),
        protocol=protocol,
        destination_port=port,
        network_zone=data["network_zone"].strip().lower(),
        timestamp=timestamp,
    )
