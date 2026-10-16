"""Receive validated network-security events over MQTT."""

from collections.abc import Callable

import paho.mqtt.client as mqtt
from paho.mqtt.client import MQTTMessage

from securesense.domain.telemetry.models import NetworkEvent
from securesense.infrastructure.mqtt.network_event_adapter import (
    NetworkEventValidationError,
    parse_network_event,
)

NetworkEventHandler = Callable[[NetworkEvent], None]
ErrorHandler = Callable[[str], None]

DEFAULT_NETWORK_EVENT_TOPIC = "securesense/network-events"


class MqttNetworkEventSubscriber:
    """Subscribe to explicit network events and deliver validated objects."""

    def __init__(
        self,
        on_event: NetworkEventHandler,
        on_error: ErrorHandler | None = None,
        host: str = "127.0.0.1",
        port: int = 1883,
        topic: str = DEFAULT_NETWORK_EVENT_TOPIC,
    ) -> None:
        if not host.strip():
            raise ValueError("MQTT host must not be empty")
        if not 1 <= port <= 65535:
            raise ValueError("MQTT port must be between 1 and 65535")
        if not topic.strip():
            raise ValueError("MQTT topic must not be empty")

        self.on_event = on_event
        self.on_error = on_error or (lambda message: None)
        self.host = host
        self.port = port
        self.topic = topic

        self.client = mqtt.Client(
            callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
            client_id="securesense-network-events",
        )
        self.client.on_connect = self._on_connect
        self.client.on_message = self._on_message

    def _on_connect(
        self,
        client: mqtt.Client,
        userdata: object,
        flags: mqtt.ConnectFlags,
        reason_code: mqtt.ReasonCode,
        properties: mqtt.Properties | None,
    ) -> None:
        """Subscribe on each successful connection, including reconnects."""
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
        """Reject invalid events and isolate consumer callback failures."""
        try:
            event = parse_network_event(message.payload)
        except NetworkEventValidationError as exc:
            self.on_error(f"Rejected network event on topic '{message.topic}': {exc}")
            return

        try:
            self.on_event(event)
        except Exception as exc:
            self.on_error(
                f"Network event handler failed for topic '{message.topic}': {exc}"
            )

    def start(self) -> None:
        """Connect and process events until interrupted."""
        self.client.connect(self.host, self.port, keepalive=60)
        self.client.loop_forever()

    def stop(self) -> None:
        """Disconnect the MQTT client."""
        self.client.disconnect()
