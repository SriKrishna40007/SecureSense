"""Tests for the MQTT network-event subscriber."""

from unittest.mock import Mock

import paho.mqtt.client as mqtt

from securesense.domain.policies.models import Protocol
from securesense.infrastructure.mqtt.network_event_subscriber import (
    MqttNetworkEventSubscriber,
)


def make_subscriber():
    events = []
    errors = []
    subscriber = MqttNetworkEventSubscriber(
        on_event=events.append,
        on_error=errors.append,
    )
    return subscriber, events, errors


def test_subscribes_after_connection_and_again_after_reconnect() -> None:
    subscriber, _, errors = make_subscriber()
    client = Mock()
    client.subscribe.return_value = (mqtt.MQTT_ERR_SUCCESS, 1)
    success = mqtt.ReasonCode(mqtt.PacketTypes.CONNACK, "Success")

    for _ in range(2):
        subscriber._on_connect(client, None, Mock(), success, None)

    assert client.subscribe.call_count == 2
    client.subscribe.assert_called_with(
        "securesense/network-events",
        qos=1,
    )
    assert errors == []


def test_delivers_valid_network_event() -> None:
    subscriber, events, errors = make_subscriber()
    message = Mock()
    message.topic = "securesense/network-events"
    message.payload = (
        b'{"device_id":"TEMP-001","source_ip":"192.0.2.10",'
        b'"destination":"mqtt-gateway","destination_ip":"192.0.2.20",'
        b'"protocol":"mqtt","destination_port":8883,'
        b'"network_zone":"iot","timestamp":"2026-10-10T08:00:00+00:00"}'
    )

    subscriber._on_message(Mock(), None, message)

    assert len(events) == 1
    assert events[0].device_id == "TEMP-001"
    assert events[0].protocol is Protocol.MQTT
    assert errors == []


def test_rejects_invalid_event_without_calling_handler() -> None:
    subscriber, events, errors = make_subscriber()
    message = Mock()
    message.topic = "securesense/network-events"
    message.payload = b"not-json"

    subscriber._on_message(Mock(), None, message)

    assert events == []
    assert len(errors) == 1
    assert "rejected network event" in errors[0].lower()


def test_handler_failure_is_reported_without_escaping_callback() -> None:
    errors = []
    subscriber = MqttNetworkEventSubscriber(
        on_event=Mock(side_effect=RuntimeError("simulated handler failure")),
        on_error=errors.append,
    )
    message = Mock()
    message.topic = "securesense/network-events"
    message.payload = (
        b'{"device_id":"TEMP-001","source_ip":"192.0.2.10",'
        b'"destination":"mqtt-gateway","destination_ip":"192.0.2.20",'
        b'"protocol":"mqtt","destination_port":8883,'
        b'"network_zone":"iot","timestamp":"2026-10-10T08:00:00+00:00"}'
    )

    subscriber._on_message(Mock(), None, message)

    assert len(errors) == 1
    assert "handler failed" in errors[0].lower()
