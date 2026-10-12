from datetime import UTC, datetime

from securesense.application.incident_service import IncidentService
from securesense.application.response_service import ResponseService
from securesense.domain.incidents.models import Incident
from securesense.domain.response.models import ResponseAction, ResponseExecutionMode


def make_services() -> tuple[IncidentService, ResponseService]:
    incidents = IncidentService()
    incident = Incident(
        incident_id="INC-0001",
        title="Unauthorized network communication",
        device_id="TEMP-001",
        risk_score=70,
        created_at=datetime(2026, 10, 10, 8, 0, tzinfo=UTC),
        updated_at=datetime(2026, 10, 10, 8, 0, tzinfo=UTC),
    )
    incidents._incidents[incident.incident_id] = incident
    return incidents, ResponseService(incidents)


def test_response_recommendation_is_auditable() -> None:
    incidents, responses = make_services()

    record = responses.recommend(
        incident_id="INC-0001",
        action=ResponseAction.RECOMMEND_CONTAINMENT,
        reason="Review repeated unauthorized communication",
        actor="analyst",
    )

    assert record.incident_id == "INC-0001"
    assert record.device_id == "TEMP-001"
    assert record.mode is ResponseExecutionMode.DRY_RUN
    assert record.executed is False
    assert record.reason == "Review repeated unauthorized communication"
    assert record.actor == "analyst"
    assert incidents.get("INC-0001").status.value == "open"
    assert incidents.get("INC-0001").history == []


def test_multiple_recommendations_are_kept_in_order() -> None:
    _, responses = make_services()

    first = responses.recommend(
        "INC-0001",
        ResponseAction.INVESTIGATE,
        "Review network evidence",
        "analyst",
    )
    second = responses.recommend(
        "INC-0001",
        ResponseAction.ESCALATE,
        "Request security-team review",
        "analyst",
    )

    assert [record.response_id for record in responses.list_records()] == [
        "RESP-0001",
        "RESP-0002",
    ]
    assert responses.get(first.response_id) == first
    assert responses.get(second.response_id) == second
