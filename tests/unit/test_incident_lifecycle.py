from datetime import UTC, datetime, timedelta

import pytest

from securesense.domain.incidents.models import (
    Incident,
    IncidentStatus,
)


@pytest.fixture
def incident() -> Incident:
    now = datetime.now(UTC)
    return Incident(
        incident_id="INC-0001",
        title="Unauthorized IoT network communication",
        device_id="TEMP-001",
        risk_score=70,
        created_at=now,
        updated_at=now,
    )


def test_incident_starts_open(incident: Incident) -> None:
    assert incident.status is IncidentStatus.OPEN
    assert incident.risk_score == 70


def test_valid_transition_is_recorded_in_audit_history(
    incident: Incident,
) -> None:
    transitioned_at = incident.created_at + timedelta(minutes=1)

    incident.transition_to(
        new_status=IncidentStatus.INVESTIGATING,
        actor="security-analyst",
        note="Reviewing unauthorized destination",
        at=transitioned_at,
    )

    assert incident.status is IncidentStatus.INVESTIGATING
    assert incident.updated_at == transitioned_at
    assert len(incident.history) == 1
    assert incident.history[0].actor == "security-analyst"
    assert incident.history[0].note == "Reviewing unauthorized destination"


def test_invalid_transition_is_rejected(incident: Incident) -> None:
    with pytest.raises(ValueError, match="Invalid incident transition"):
        incident.transition_to(
            new_status=IncidentStatus.CLOSED,
            actor="security-analyst",
            note="Attempted to close without investigation",
            at=incident.created_at + timedelta(minutes=1),
        )

    assert incident.status is IncidentStatus.OPEN
    assert incident.history == []


def test_transition_rejects_naive_timestamp(incident: Incident) -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        incident.transition_to(
            new_status=IncidentStatus.INVESTIGATING,
            actor="security-analyst",
            note="Begin investigation",
            at=datetime(2026, 1, 1),  # noqa: DTZ001
        )


def test_transition_rejects_timestamp_before_last_update(
    incident: Incident,
) -> None:
    with pytest.raises(ValueError, match="must not precede"):
        incident.transition_to(
            new_status=IncidentStatus.INVESTIGATING,
            actor="security-analyst",
            note="Begin investigation",
            at=incident.created_at - timedelta(seconds=1),
        )


def test_closed_incident_cannot_be_reopened_directly(
    incident: Incident,
) -> None:
    base = incident.created_at

    incident.transition_to(
        new_status=IncidentStatus.INVESTIGATING,
        actor="security-analyst",
        note="Investigate event",
        at=base + timedelta(minutes=1),
    )
    incident.transition_to(
        new_status=IncidentStatus.RESOLVED,
        actor="security-analyst",
        note="Communication policy corrected",
        at=base + timedelta(minutes=2),
    )
    incident.transition_to(
        new_status=IncidentStatus.CLOSED,
        actor="security-analyst",
        note="Evidence reviewed and incident closed",
        at=base + timedelta(minutes=3),
    )

    with pytest.raises(ValueError, match="Invalid incident transition"):
        incident.transition_to(
            new_status=IncidentStatus.INVESTIGATING,
            actor="security-analyst",
            note="Attempt to reopen closed incident",
            at=base + timedelta(minutes=4),
        )

    assert incident.status is IncidentStatus.CLOSED
    assert len(incident.history) == 3
