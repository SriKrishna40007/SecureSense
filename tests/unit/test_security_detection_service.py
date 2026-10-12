from datetime import UTC, datetime

import pytest

from securesense.application.device_registry import DeviceRegistry
from securesense.application.device_security_service import DeviceSecurityService
from securesense.application.security_detection_service import (
    SecurityDetectionService,
)
from securesense.domain.devices.models import Device, DeviceType, NetworkZone
from securesense.domain.policies.evaluator import PolicyEvaluator
from securesense.domain.policies.models import CommunicationPolicy, Protocol
from securesense.domain.telemetry.models import NetworkEvent


@pytest.fixture
def detector() -> SecurityDetectionService:
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
    security_service = DeviceSecurityService(
        registry=registry,
        policy_evaluator=PolicyEvaluator(),
    )
    return SecurityDetectionService(security_service)


def make_event(
    *,
    device_id: str = "TEMP-001",
    destination: str = "mqtt-gateway",
    protocol: Protocol = Protocol.MQTT,
    port: int = 8883,
) -> NetworkEvent:
    return NetworkEvent(
        device_id=device_id,
        source_ip="192.0.2.10",
        destination=destination,
        destination_ip="192.0.2.20",
        protocol=protocol,
        destination_port=port,
        network_zone=NetworkZone.IOT.value,
        timestamp=datetime(2026, 10, 10, 8, 0, tzinfo=UTC),
    )


def test_allowed_event_produces_no_finding(
    detector: SecurityDetectionService,
) -> None:
    result = detector.evaluate(make_event())

    assert result.decision.allowed is True
    assert result.finding is None


def test_policy_violation_produces_evidence_backed_finding(
    detector: SecurityDetectionService,
) -> None:
    event = make_event(destination="unknown-host", port=4444)

    result = detector.evaluate(event)

    assert result.decision.allowed is False
    assert result.finding is not None
    assert result.finding.rule_id == "NET-001"
    assert result.finding.device_id == "TEMP-001"
    assert result.finding.evidence["destination"] == "unknown-host"
    assert result.finding.evidence["destination_port"] == 4444
    assert result.finding.evidence["policy_reason"] == result.decision.reason
    assert result.finding.observed_at == event.timestamp


def test_unknown_device_produces_dedicated_finding(
    detector: SecurityDetectionService,
) -> None:
    event = make_event(device_id="UNKNOWN-999")

    result = detector.evaluate(event)

    assert result.decision.allowed is False
    assert result.finding is not None
    assert result.finding.rule_id == "NET-002"
    assert result.finding.device_id == "UNKNOWN-999"
    assert result.finding.evidence["device_id"] == "UNKNOWN-999"
