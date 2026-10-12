from datetime import UTC, datetime

from securesense.application.device_registry import DeviceRegistry
from securesense.application.device_security_service import DeviceSecurityService
from securesense.application.incident_service import IncidentService
from securesense.application.reporting.investigation_report import (
    InvestigationReportFormatter,
)
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
from securesense.domain.response.models import ResponseAction
from securesense.domain.risk.scorer import RiskScorer
from securesense.domain.telemetry.models import NetworkEvent


def make_investigator() -> SecurityInvestigationService:
    registry = DeviceRegistry()
    registry.register(
        Device(
            "TEMP-001",
            DeviceType.TEMPERATURE_SENSOR,
            "Monitor machine temperature",
            NetworkZone.IOT,
        ),
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


def make_event(source_ip: str, destination_ip: str, minute: int) -> NetworkEvent:
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


def test_report_summarizes_findings_risk_and_incidents() -> None:
    investigator = make_investigator()
    result = investigator.investigate(
        [make_event("192.0.2.10", "192.0.2.20", 0)]
    )

    report = InvestigationReportFormatter().format(result)

    assert "SECURESENSE INVESTIGATION REPORT" in report
    assert "Findings: 1" in report
    assert "NET-001" in report
    assert "Risk score: 70/100" in report
    assert "INC-0001" in report
    assert "open" in report.lower()


def test_report_includes_candidate_attack_path_evidence() -> None:
    investigator = make_investigator()
    result = investigator.investigate(
        [
            make_event("192.0.2.10", "192.0.2.20", 0),
            make_event("192.0.2.20", "192.0.2.30", 1),
        ]
    )

    report = InvestigationReportFormatter().format(result)

    assert "Candidate attack paths: 1" in report
    assert "192.0.2.20" in report
    assert "candidate" in report.lower()


def test_report_labels_response_recommendations_as_dry_run() -> None:
    investigator = make_investigator()
    result = investigator.investigate(
        [make_event("192.0.2.10", "192.0.2.20", 0)]
    )
    incident = result.event_results[0].incident
    assert incident is not None

    investigator.recommend_response(
        incident_id=incident.incident_id,
        action=ResponseAction.RECOMMEND_CONTAINMENT,
        reason="Review evidence before deciding on containment",
        actor="analyst",
    )

    responses = investigator._response_service.list_records()  # type: ignore[union-attr]
    report = InvestigationReportFormatter().format(result, responses)

    assert "DRY RUN — NOT EXECUTED" in report
    assert "RESP-0001" in report
    assert "recommend_containment" in report
