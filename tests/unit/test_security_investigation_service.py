from datetime import UTC, datetime

from securesense.application.device_registry import DeviceRegistry
from securesense.application.device_security_service import DeviceSecurityService
from securesense.application.incident_service import IncidentService
from securesense.application.response_service import ResponseService
from securesense.application.security_detection_service import SecurityDetectionService
from securesense.application.security_investigation_service import (
    SecurityInvestigationService,
)
from securesense.application.security_pipeline_service import SecurityPipelineService
from securesense.domain.attack_paths.correlator import AttackPathCorrelator
from securesense.domain.devices.models import Device, DeviceType, NetworkZone
from securesense.domain.policies.evaluator import PolicyEvaluator
from securesense.domain.policies.models import CommunicationPolicy, Protocol
from securesense.domain.response.models import (
    ResponseAction,
    ResponseExecutionMode,
)
from securesense.domain.risk.scorer import RiskScorer
from securesense.domain.telemetry.models import NetworkEvent


def make_investigator() -> SecurityInvestigationService:
    registry = DeviceRegistry()
    registry.register(
        Device("TEMP-001", DeviceType.TEMPERATURE_SENSOR,
               "Monitor machine temperature", NetworkZone.IOT),
        CommunicationPolicy(
            "TEMP-001",
            frozenset({Protocol.MQTT}),
            frozenset({"mqtt-gateway"}),
            frozenset({8883}),
            frozenset({NetworkZone.IOT.value}),
        ),
    )
    pipeline = SecurityPipelineService(
        SecurityDetectionService(
            DeviceSecurityService(registry, PolicyEvaluator())
        ),
        RiskScorer(),
        IncidentService(),
    )
    return SecurityInvestigationService(
        pipeline,
        AttackPathCorrelator(),
        ResponseService(pipeline.incidents),
    )


def make_event(
    source_ip: str,
    destination_ip: str,
    minute: int,
) -> NetworkEvent:
    return NetworkEvent(
        device_id="TEMP-001",
        source_ip=source_ip,
        destination="unapproved-host",
        destination_ip=destination_ip,
        protocol=Protocol.MQTT,
        destination_port=4444,
        network_zone=NetworkZone.IOT.value,
        timestamp=datetime(2026, 10, 10, 8, minute, tzinfo=UTC),
    )


def test_links_correlated_attack_path_to_incidents() -> None:
    investigator = make_investigator()
    events = [
        make_event("192.0.2.10", "192.0.2.20", 0),
        make_event("192.0.2.20", "192.0.2.30", 1),
    ]

    result = investigator.investigate(events)

    assert len(result.event_results) == 2
    assert len(result.correlated_paths) == 1

    linked = result.correlated_paths[0]
    assert linked.path.shared_ips == ("192.0.2.20",)
    assert len(linked.incidents) == 2
    assert [item.incident_id for item in linked.incidents] == [
        "INC-0001",
        "INC-0002",
    ]


def test_unrelated_events_produce_no_candidate_path() -> None:
    investigator = make_investigator()
    events = [
        make_event("192.0.2.10", "192.0.2.20", 0),
        make_event("192.0.2.30", "192.0.2.40", 1),
    ]

    result = investigator.investigate(events)

    assert len(result.event_results) == 2
    assert result.correlated_paths == ()


def test_allowed_events_create_no_incidents_or_paths() -> None:
    investigator = make_investigator()
    event = NetworkEvent(
        device_id="TEMP-001",
        source_ip="192.0.2.10",
        destination="mqtt-gateway",
        destination_ip="192.0.2.20",
        protocol=Protocol.MQTT,
        destination_port=8883,
        network_zone=NetworkZone.IOT.value,
        timestamp=datetime(2026, 10, 10, 8, 0, tzinfo=UTC),
    )

    result = investigator.investigate([event])

    assert result.event_results[0].incident is None
    assert result.correlated_paths == ()



def test_investigation_can_recommend_dry_run_response() -> None:
    investigator = make_investigator()
    result = investigator.investigate(
        [make_event("192.0.2.10", "192.0.2.20", 0)]
    )
    incident = result.event_results[0].incident

    assert incident is not None

    record = investigator.recommend_response(
        incident_id=incident.incident_id,
        action=ResponseAction.RECOMMEND_CONTAINMENT,
        reason="Review unauthorized communication before containment",
        actor="analyst",
    )

    assert record.incident_id == incident.incident_id
    assert record.mode is ResponseExecutionMode.DRY_RUN
    assert record.executed is False
    assert incident.status.value == "open"
    assert incident.history == []
