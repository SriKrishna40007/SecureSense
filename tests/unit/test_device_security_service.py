from datetime import UTC, datetime

import pytest

from securesense.application.device_registry import DeviceRegistry
from securesense.application.device_security_service import DeviceSecurityService
from securesense.domain.devices.models import Device, DeviceType, NetworkZone
from securesense.domain.policies.evaluator import PolicyEvaluator
from securesense.domain.policies.models import CommunicationPolicy, Protocol
from securesense.domain.telemetry.models import NetworkEvent


@pytest.fixture
def registry() -> DeviceRegistry:
    registry = DeviceRegistry()
    registry.register(
        device=Device(
            device_id="TEMP-001",
            device_type=DeviceType.TEMPERATURE_SENSOR,
            purpose="Monitor machine temperature",
            network_zone=NetworkZone.IOT,
        ),
        policy=CommunicationPolicy(
            device_id="TEMP-001",
            allowed_protocols=frozenset({Protocol.MQTT}),
            allowed_destinations=frozenset({"mqtt-gateway"}),
            allowed_ports=frozenset({8883}),
            allowed_network_zones=frozenset({NetworkZone.IOT.value}),
        ),
    )
    return registry


@pytest.fixture
def service(registry: DeviceRegistry) -> DeviceSecurityService:
    return DeviceSecurityService(
        registry=registry,
        policy_evaluator=PolicyEvaluator(),
    )


def make_event(
    *,
    device_id: str = "TEMP-001",
    destination: str = "mqtt-gateway",
    protocol: Protocol = Protocol.MQTT,
    port: int = 8883,
    network_zone: str = NetworkZone.IOT.value,
) -> NetworkEvent:
    return NetworkEvent(
        device_id=device_id,
        source_ip="192.0.2.10",
        destination=destination,
        destination_ip="192.0.2.20",
        protocol=protocol,
        destination_port=port,
        network_zone=network_zone,
        timestamp=datetime.now(UTC),
    )


def test_allows_registered_device_with_expected_communication(
    service: DeviceSecurityService,
) -> None:
    decision = service.evaluate_event(make_event())

    assert decision.allowed is True
    assert decision.reason == (
        "Communication matches the device security policy"
    )


def test_denies_unapproved_destination(
    service: DeviceSecurityService,
) -> None:
    decision = service.evaluate_event(
        make_event(destination="unknown-host")
    )

    assert decision.allowed is False
    assert "Destination 'unknown-host' is not allowed" in decision.reason


def test_denies_unapproved_port(
    service: DeviceSecurityService,
) -> None:
    decision = service.evaluate_event(make_event(port=4444))

    assert decision.allowed is False
    assert "Port '4444' is not allowed" in decision.reason


def test_denies_unknown_device(
    service: DeviceSecurityService,
) -> None:
    decision = service.evaluate_event(
        make_event(device_id="UNKNOWN-999")
    )

    assert decision.allowed is False
    assert "UNKNOWN-999" in decision.reason
    assert "not registered" in decision.reason
