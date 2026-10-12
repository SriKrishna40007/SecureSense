import pytest

from securesense.application.device_registry import DeviceRegistry
from securesense.domain.devices.models import Device, DeviceType, NetworkZone
from securesense.domain.policies.models import CommunicationPolicy, Protocol


def make_device(device_id: str = "TEMP-001") -> Device:
    return Device(
        device_id=device_id,
        device_type=DeviceType.TEMPERATURE_SENSOR,
        purpose="Monitor machine temperature",
        network_zone=NetworkZone.IOT,
    )


def make_policy(device_id: str = "TEMP-001") -> CommunicationPolicy:
    return CommunicationPolicy(
        device_id=device_id,
        allowed_protocols=frozenset({Protocol.MQTT}),
        allowed_destinations=frozenset({"mqtt-gateway"}),
        allowed_ports=frozenset({8883}),
        allowed_network_zones=frozenset({"iot"}),
    )


def test_register_and_retrieve_device() -> None:
    registry = DeviceRegistry()
    device = make_device()
    policy = make_policy()

    registry.register(device, policy)

    registered = registry.get("TEMP-001")

    assert registered.device == device
    assert registered.policy == policy


def test_list_devices_returns_registered_devices() -> None:
    registry = DeviceRegistry()

    registry.register(make_device(), make_policy())
    registry.register(
        make_device("VIB-001"),
        make_policy("VIB-001"),
    )

    devices = registry.list_devices()

    assert len(devices) == 2
    assert {item.device.device_id for item in devices} == {
        "TEMP-001",
        "VIB-001",
    }


def test_duplicate_device_registration_is_rejected() -> None:
    registry = DeviceRegistry()

    registry.register(make_device(), make_policy())

    with pytest.raises(
        ValueError,
        match="already registered",
    ):
        registry.register(make_device(), make_policy())


def test_mismatched_policy_is_rejected() -> None:
    registry = DeviceRegistry()

    with pytest.raises(
        ValueError,
        match="identifiers must match",
    ):
        registry.register(
            make_device("TEMP-001"),
            make_policy("VIB-001"),
        )


def test_unknown_device_is_rejected() -> None:
    registry = DeviceRegistry()

    with pytest.raises(
        KeyError,
        match="not registered",
    ):
        registry.get("UNKNOWN-001")
