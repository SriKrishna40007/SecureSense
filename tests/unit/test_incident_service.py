from datetime import UTC, datetime

import pytest

from securesense.application.incident_service import IncidentService
from securesense.domain.findings.models import (
    FindingSeverity,
    SecurityFinding,
)
from securesense.domain.risk.scorer import RiskScorer


@pytest.fixture
def finding() -> SecurityFinding:
    return SecurityFinding(
        rule_id="NET-001",
        title="Unauthorized network communication",
        severity=FindingSeverity.HIGH,
        device_id="TEMP-001",
        description="Unexpected destination detected.",
        evidence={"destination_ip": "192.0.2.20"},
        recommendation="Review the destination and communication policy.",
        observed_at=datetime(2026, 10, 10, 10, 0, tzinfo=UTC),
    )


def test_creates_incident_from_finding_and_risk(
    finding: SecurityFinding,
) -> None:
    service = IncidentService()
    assessment = RiskScorer().assess(finding)

    incident = service.create_from_finding(finding, assessment)

    assert incident.incident_id == "INC-0001"
    assert incident.title == finding.title
    assert incident.device_id == finding.device_id
    assert incident.risk_score == assessment.score
    assert incident.status.value == "open"


def test_assigns_unique_ids_to_incidents(
    finding: SecurityFinding,
) -> None:
    service = IncidentService()
    assessment = RiskScorer().assess(finding)

    first = service.create_from_finding(finding, assessment)
    second = service.create_from_finding(finding, assessment)

    assert first.incident_id == "INC-0001"
    assert second.incident_id == "INC-0002"


def test_retrieves_incident_by_id(finding: SecurityFinding) -> None:
    service = IncidentService()
    assessment = RiskScorer().assess(finding)
    created = service.create_from_finding(finding, assessment)

    assert service.get(created.incident_id) is created


def test_unknown_incident_id_raises_key_error() -> None:
    service = IncidentService()

    with pytest.raises(KeyError, match="INC-9999"):
        service.get("INC-9999")


def test_lists_created_incidents(finding: SecurityFinding) -> None:
    service = IncidentService()
    assessment = RiskScorer().assess(finding)

    first = service.create_from_finding(finding, assessment)
    second = service.create_from_finding(finding, assessment)

    assert service.list_incidents() == [first, second]


def test_rejects_risk_assessment_for_another_finding(
    finding: SecurityFinding,
) -> None:
    from dataclasses import replace

    service = IncidentService()
    assessment = RiskScorer().assess(finding)
    unrelated_assessment = replace(assessment, device_id="PRESS-001")

    with pytest.raises(ValueError, match="does not match"):
        service.create_from_finding(finding, unrelated_assessment)

    assert service.list_incidents() == []


def test_service_transition_survives_repository_reopen(
    finding: SecurityFinding,
    tmp_path,
) -> None:
    from securesense.domain.incidents.models import IncidentStatus
    from securesense.infrastructure.persistence.sqlite_incident_repository import (
        SQLiteIncidentRepository,
    )

    database = tmp_path / "incident-lifecycle.sqlite3"
    service = IncidentService(SQLiteIncidentRepository(database))
    incident = service.create_from_finding(
        finding,
        RiskScorer().assess(finding),
    )

    transitioned = service.transition(
        incident_id=incident.incident_id,
        new_status=IncidentStatus.INVESTIGATING,
        actor="security-analyst",
        note="Investigating suspicious device communication",
    )

    restored = IncidentService(SQLiteIncidentRepository(database)).get(
        incident.incident_id
    )

    assert transitioned.status is IncidentStatus.INVESTIGATING
    assert restored.status is IncidentStatus.INVESTIGATING
    assert len(restored.history) == 1
    assert restored.history[0].previous_status is IncidentStatus.OPEN
    assert restored.history[0].new_status is IncidentStatus.INVESTIGATING
    assert restored.history[0].actor == "security-analyst"
    assert restored.history[0].note == ("Investigating suspicious device communication")
    assert restored.updated_at == restored.history[0].occurred_at
