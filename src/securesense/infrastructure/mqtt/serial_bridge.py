"""Bridge Wokwi serial temperature readings to local MQTT."""

import json
import re
import sys
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import TextIO

import paho.mqtt.client as mqtt

DEVICE_ID = "TEMP-001"
TOPIC = f"securesense/devices/{DEVICE_ID}/telemetry"

TEMPERATURE_PATTERN = re.compile(
    r"TEMP-001 temperature=(-?\d+(?:\.\d+)?) C"
)


def publish_serial_readings(
    lines: Iterable[str],
    client: mqtt.Client,
    output: TextIO = sys.stdout,
) -> int:
    """Publish recognized sensor readings and return the count."""
    published = 0

    for line in lines:
        match = TEMPERATURE_PATTERN.search(line)
        if match is None:
            continue

        temperature = float(match.group(1))
        if not -40.0 <= temperature <= 80.0:
            print(
                f"Rejected out-of-range temperature: {temperature}",
                file=sys.stderr,
            )
            continue

        payload = json.dumps(
            {
                "device_id": DEVICE_ID,
                "metric": "temperature",
                "value": temperature,
                "unit": "celsius",
                "timestamp": datetime.now(UTC).isoformat(),
            }
        )

        result = client.publish(TOPIC, payload, qos=1)
        if result.rc != mqtt.MQTT_ERR_SUCCESS:
            raise RuntimeError(f"MQTT publish failed: {result.rc}")

        result.wait_for_publish(timeout=5)
        if not result.is_published():
            raise RuntimeError("MQTT publish did not complete within 5 seconds")

        published += 1
        print(f"Published {DEVICE_ID} temperature={temperature:.2f} C", file=output)
        output.flush()

    return published


def main() -> int:
    """Read Wokwi serial output from stdin and publish matching readings."""
    client = mqtt.Client(
        callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
        client_id="securesense-wokwi-bridge",
    )

    try:
        client.connect("127.0.0.1", 1883, keepalive=60)
        client.loop_start()
        count = publish_serial_readings(sys.stdin, client)
        print(f"Bridge finished; published {count} reading(s).")
        return 0 if count else 1
    except (OSError, RuntimeError) as exc:
        print(f"Bridge error: {exc}", file=sys.stderr)
        return 1
    finally:
        if client.is_connected():
            client.disconnect()
        client.loop_stop()


if __name__ == "__main__":
    raise SystemExit(main())
