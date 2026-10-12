from datetime import UTC, datetime
from unittest.mock import Mock

import paho.mqtt.client as mqtt
import pytest

from securesense.domain.telemetry.sensor_reading import SensorReading
from securesense.infrastructure.mqtt.subscriber import MqttTelemetrySubscriber


def make_subscriber():
    readings = []
    errors = []

    subscriber = MqttTelemetrySubscriber(
        on_reading=readings.append,
        on_error=errors.append,
    )
    return subscriber, readings, errors


def test_subscribes_after_successful_connection():
    subscriber, _, errors = make_subscriber()
    client = Mock()
    client.subscribe.return_value = (mqtt.MQTT_ERR_SUCCESS, 1)

    subscriber._on_connect(
        client,
        None,
        Mock(),
        mqtt.ReasonCode(mqtt.PacketTypes.CONNACK, "Success"),
        None,
    )

    client.subscribe.assert_called_once_with(
        "securesense/devices/+/telemetry", qos=1
    )
    assert errors == []


def test_reports_connection_failure():
    subscriber, _, errors = make_subscriber()
    client = Mock()

    subscriber._on_connect(
        client,
        None,
        Mock(),
        mqtt.ReasonCode(mqtt.PacketTypes.CONNACK, "Not authorized"),
        None,
    )

    client.subscribe.assert_not_called()
    assert len(errors) == 1
    assert "connection failed" in errors[0].lower()


def test_delivers_valid_sensor_reading():
    subscriber, readings, errors = make_subscriber()
    message = Mock()
    message.topic = "securesense/devices/TEMP-001/telemetry"
    message.payload = (
        b'{"device_id":"TEMP-001","metric":"temperature",'
        b'"value":24.0,"unit":"celsius",'
        b'"timestamp":"2026-10-10T06:00:00+00:00"}'
    )

    subscriber._on_message(Mock(), None, message)

    assert readings == [
        SensorReading(
            device_id="TEMP-001",
            metric="temperature",
            value=24.0,
            unit="celsius",
            timestamp=datetime(2026, 10, 10, 6, 0, tzinfo=UTC),
        )
    ]
    assert errors == []


def test_reports_invalid_payload_without_crashing():
    subscriber, readings, errors = make_subscriber()
    message = Mock()
    message.topic = "securesense/devices/TEMP-001/telemetry"
    message.payload = b"not-json"

    subscriber._on_message(Mock(), None, message)

    assert readings == []
    assert len(errors) == 1
    assert "rejected telemetry" in errors[0].lower()


@pytest.mark.parametrize(
    ("host", "port", "topic"),
    [
        ("", 1883, "sensors/telemetry"),
        ("127.0.0.1", 0, "sensors/telemetry"),
        ("127.0.0.1", 65536, "sensors/telemetry"),
        ("127.0.0.1", 1883, ""),
    ],
)
def test_rejects_invalid_configuration(host, port, topic):
    with pytest.raises(ValueError):
        MqttTelemetrySubscriber(
            on_reading=lambda reading: None,
            host=host,
            port=port,
            topic=topic,
        )
