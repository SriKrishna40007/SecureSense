from datetime import UTC, datetime

import pytest

from securesense.application.device_registry import DeviceRegistry
from securesense.application.device_security_service import DeviceSecurityService
from securesense.application.incident_service import IncidentService
from securesense.application.security_detection_service import (
    SecurityDetectionService,
)
from securesense.application.security_pipeline_service import (
    SecurityPipelineService,
)
from securesense.domain.devices.models import Device, DeviceType, NetworkZone
from securesense.domain.policies.evaluator import PolicyEvaluator
from securesense.domain.policies.models import CommunicationPolicy, Protocol
from securesense.domain.risk.scorer import RiskScorer
from securesense.domain.telemetry.models import NetworkEvent


@pytest.fixture
def pipeline() -> SecurityPipelineService:
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
    detector = SecurityDetectionService(
        DeviceSecurityService(registry, PolicyEvaluator())
    )
    return SecurityPipelineService(
        detector=detector,
        risk_scorer=RiskScorer(),
        incident_service=IncidentService(),
    )


def make_event(
    device_id: str = "TEMP-001",
    destination: str = "mqtt-gateway",
    port: int = 8883,
) -> NetworkEvent:
    return NetworkEvent(
        device_id=device_id,
        source_ip="192.0.2.10",
        destination=destination,
        destination_ip="192.0.2.20",
        protocol=Protocol.MQTT,
        destination_port=port,
        network_zone=NetworkZone.IOT.value,
        timestamp=datetime(2026, 10, 10, 8, 0, tzinfo=UTC),
    )


def test_allowed_event_creates_no_finding_or_incident(
    pipeline: SecurityPipelineService,
) -> None:
    result = pipeline.process(make_event())

    assert result.detection.decision.allowed is True
    assert result.detection.finding is None
    assert result.risk_assessment is None
    assert result.incident is None
    assert pipeline.incidents.list_incidents() == []


def test_policy_violation_creates_risk_assessment_and_incident(
    pipeline: SecurityPipelineService,
) -> None:
    result = pipeline.process(make_event(destination="unknown-host", port=4444))

    assert result.detection.finding is not None
    assert result.detection.finding.rule_id == "NET-001"
    assert result.risk_assessment is not None
    assert result.risk_assessment.score == 70
    assert result.incident is not None
    assert result.incident.incident_id == "INC-0001"
    assert result.incident.device_id == "TEMP-001"
    assert result.incident.risk_score == result.risk_assessment.score


def test_unknown_device_creates_incident(
    pipeline: SecurityPipelineService,
) -> None:
    result = pipeline.process(make_event(device_id="UNKNOWN-999"))

    assert result.detection.finding is not None
    assert result.detection.finding.rule_id == "NET-002"
    assert result.incident is not None
    assert result.incident.device_id == "UNKNOWN-999"


def test_multiple_violations_create_distinct_incidents(
    pipeline: SecurityPipelineService,
) -> None:
    first = pipeline.process(make_event(destination="unknown-host"))
    second = pipeline.process(make_event(port=4444))

    assert first.incident is not None
    assert second.incident is not None
    assert first.incident.incident_id == "INC-0001"
    assert second.incident.incident_id == "INC-0002"
    assert len(pipeline.incidents.list_incidents()) == 2
