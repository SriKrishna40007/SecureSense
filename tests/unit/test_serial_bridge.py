import json
from unittest.mock import Mock

import paho.mqtt.client as mqtt
import pytest

from securesense.infrastructure.mqtt.serial_bridge import (
    DEVICE_ID,
    TOPIC,
    publish_serial_readings,
)


def successful_publish():
    result = Mock()
    result.rc = mqtt.MQTT_ERR_SUCCESS
    result.is_published.return_value = True
    return result


def test_publishes_temperature_reading():
    client = Mock()
    client.publish.return_value = successful_publish()
    output = Mock()

    count = publish_serial_readings(
        [
            "SecureSense TEMP-001\n",
            "TEMP-001 temperature=24.00 C\n",
        ],
        client,
        output,
    )

    assert count == 1
    client.publish.assert_called_once()
    topic, payload = client.publish.call_args.args
    message = json.loads(payload)

    assert topic == TOPIC
    assert message["device_id"] == DEVICE_ID
    assert message["metric"] == "temperature"
    assert message["value"] == 24.0
    assert message["unit"] == "celsius"
    assert message["timestamp"].endswith("+00:00")


def test_ignores_unrelated_serial_output():
    client = Mock()
    output = Mock()

    count = publish_serial_readings(
        [
            "SecureSense TEMP-001\n",
            "Temperature sensor starting...\n",
            "ERROR: Failed to read temperature\n",
        ],
        client,
        output,
    )

    assert count == 0
    client.publish.assert_not_called()


@pytest.mark.parametrize("temperature", [-40.1, 80.1, 999.0])
def test_rejects_out_of_range_temperature(temperature, capsys):
    client = Mock()

    count = publish_serial_readings(
        [f"TEMP-001 temperature={temperature} C\n"],
        client,
    )

    assert count == 0
    client.publish.assert_not_called()
    assert "Rejected out-of-range temperature" in capsys.readouterr().err


def test_reports_publish_failure():
    client = Mock()
    result = Mock()
    result.rc = mqtt.MQTT_ERR_NO_CONN
    client.publish.return_value = result

    with pytest.raises(RuntimeError, match="MQTT publish failed"):
        publish_serial_readings(
            ["TEMP-001 temperature=24.00 C\n"],
            client,
        )


def test_reports_unconfirmed_publish():
    client = Mock()
    result = successful_publish()
    result.is_published.return_value = False
    client.publish.return_value = result

    with pytest.raises(RuntimeError, match="did not complete"):
        publish_serial_readings(
            ["TEMP-001 temperature=24.00 C\n"],
            client,
        )

def test_main_configures_mqtt_authentication(monkeypatch):
    from securesense.infrastructure.mqtt import serial_bridge

    client = Mock()
    monkeypatch.setattr(serial_bridge.mqtt, "Client", Mock(return_value=client))
    monkeypatch.setenv("SECURESENSE_MQTT_USERNAME", "test-user")
    monkeypatch.setenv("SECURESENSE_MQTT_PASSWORD", "test-password")
    monkeypatch.setenv("SECURESENSE_MQTT_PORT", "2883")
    monkeypatch.setattr(serial_bridge.sys, "stdin", ["unrelated output\\n"])

    assert serial_bridge.main() == 1
    client.username_pw_set.assert_called_once_with("test-user", "test-password")
    client.connect.assert_called_once_with("127.0.0.1", 2883, keepalive=60)


def test_main_rejects_incomplete_mqtt_credentials(monkeypatch):
    from securesense.infrastructure.mqtt import serial_bridge

    client_factory = Mock()
    monkeypatch.setattr(serial_bridge.mqtt, "Client", client_factory)
    monkeypatch.setenv("SECURESENSE_MQTT_USERNAME", "test-user")
    monkeypatch.delenv("SECURESENSE_MQTT_PASSWORD", raising=False)

    assert serial_bridge.main() == 1
    client_factory.return_value.connect.assert_not_called()


def test_main_connects_without_auth_when_credentials_are_absent(monkeypatch):
    from securesense.infrastructure.mqtt import serial_bridge

    client = Mock()
    monkeypatch.setattr(serial_bridge.mqtt, "Client", Mock(return_value=client))
    monkeypatch.delenv("SECURESENSE_MQTT_USERNAME", raising=False)
    monkeypatch.delenv("SECURESENSE_MQTT_PASSWORD", raising=False)
    monkeypatch.delenv("SECURESENSE_MQTT_PORT", raising=False)
    monkeypatch.setattr(serial_bridge.sys, "stdin", ["unrelated output\\n"])

    assert serial_bridge.main() == 1
    client.username_pw_set.assert_not_called()
    client.connect.assert_called_once_with("127.0.0.1", 1883, keepalive=60)
