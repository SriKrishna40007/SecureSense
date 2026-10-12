"""Receive and validate sensor telemetry over MQTT."""

from collections.abc import Callable

import paho.mqtt.client as mqtt
from paho.mqtt.client import MQTTMessage

from securesense.domain.telemetry.sensor_reading import SensorReading
from securesense.infrastructure.mqtt.telemetry_adapter import (
    TelemetryValidationError,
    parse_sensor_reading,
)

ReadingHandler = Callable[[SensorReading], None]
ErrorHandler = Callable[[str], None]

DEFAULT_TOPIC = "securesense/devices/+/telemetry"


class MqttTelemetrySubscriber:
    """Subscribe to MQTT telemetry and deliver validated readings."""

    def __init__(
        self,
        on_reading: ReadingHandler,
        on_error: ErrorHandler | None = None,
        host: str = "127.0.0.1",
        port: int = 1883,
        topic: str = DEFAULT_TOPIC,
    ) -> None:
        if not host.strip():
            raise ValueError("MQTT host must not be empty")
        if not 1 <= port <= 65535:
            raise ValueError("MQTT port must be between 1 and 65535")
        if not topic.strip():
            raise ValueError("MQTT topic must not be empty")

        self.on_reading = on_reading
        self.on_error = on_error or (lambda message: None)
        self.topic = topic

        self.client = mqtt.Client(
            callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
            client_id="securesense-telemetry",
        )
        self.client.on_connect = self._on_connect
        self.client.on_message = self._on_message

        self.host = host
        self.port = port

    def _on_connect(
        self,
        client: mqtt.Client,
        userdata: object,
        flags: mqtt.ConnectFlags,
        reason_code: mqtt.ReasonCode,
        properties: mqtt.Properties | None,
    ) -> None:
        """Subscribe after a successful broker connection."""
        if reason_code.is_failure:
            self.on_error(f"MQTT connection failed: {reason_code}")
            return

        result, _ = client.subscribe(self.topic, qos=1)
        if result != mqtt.MQTT_ERR_SUCCESS:
            self.on_error(f"Failed to subscribe to topic: {self.topic}")

    def _on_message(
        self,
        client: mqtt.Client,
        userdata: object,
        message: MQTTMessage,
    ) -> None:
        """Parse an incoming message and deliver valid sensor readings."""
        try:
            reading = parse_sensor_reading(message.payload)
        except TelemetryValidationError as exc:
            self.on_error(
                f"Rejected telemetry on topic '{message.topic}': {exc}"
            )
            return

        self.on_reading(reading)

    def start(self) -> None:
        """Connect to the broker and process messages until interrupted."""
        self.client.connect(self.host, self.port, keepalive=60)
        self.client.loop_forever()

    def stop(self) -> None:
        """Disconnect the MQTT client."""
        self.client.disconnect()
