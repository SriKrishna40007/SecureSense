from datetime import UTC, datetime

import pytest

from securesense.application.incident_service import IncidentService
from securesense.application.response_service import ResponseService
from securesense.domain.incidents.models import Incident
from securesense.domain.response.models import (
    ResponseAction,
    ResponseExecutionMode,
)


def make_incident_service() -> IncidentService:
    service = IncidentService()
    incident = Incident(
        incident_id="INC-0001",
        title="Unauthorized network communication",
        device_id="TEMP-001",
        risk_score=70,
        created_at=datetime(2026, 10, 10, 8, 0, tzinfo=UTC),
        updated_at=datetime(2026, 10, 10, 8, 0, tzinfo=UTC),
    )
    service._incidents[incident.incident_id] = incident
    return service


def test_creates_and_retrieves_dry_run_response() -> None:
    service = ResponseService(make_incident_service())

    record = service.recommend(
        incident_id="INC-0001",
        action=ResponseAction.RECOMMEND_CONTAINMENT,
        reason="Repeated unauthorized communication",
        actor="securesense",
    )

    assert record.response_id == "RESP-0001"
    assert record.incident_id == "INC-0001"
    assert record.device_id == "TEMP-001"
    assert record.mode is ResponseExecutionMode.DRY_RUN
    assert record.executed is False
    assert service.get(record.response_id) == record
    assert service.list_records() == [record]


def test_assigns_unique_response_ids() -> None:
    service = ResponseService(make_incident_service())

    first = service.recommend(
        "INC-0001",
        ResponseAction.INVESTIGATE,
        "Review the network evidence",
        "analyst",
    )
    second = service.recommend(
        "INC-0001",
        ResponseAction.ESCALATE,
        "Request security-team review",
        "analyst",
    )

    assert first.response_id == "RESP-0001"
    assert second.response_id == "RESP-0002"


def test_recommendation_does_not_change_incident_status() -> None:
    incident_service = make_incident_service()
    service = ResponseService(incident_service)

    service.recommend(
        "INC-0001",
        ResponseAction.RECOMMEND_CONTAINMENT,
        "Containment requires human review",
        "securesense",
    )

    assert incident_service.get("INC-0001").status.value == "open"
    assert incident_service.get("INC-0001").history == []


def test_unknown_incident_is_rejected() -> None:
    service = ResponseService(make_incident_service())

    with pytest.raises(KeyError, match="INC-9999"):
        service.recommend(
            "INC-9999",
            ResponseAction.INVESTIGATE,
            "Investigate unknown incident",
            "analyst",
        )


def test_unknown_response_id_is_rejected() -> None:
    service = ResponseService(make_incident_service())

    with pytest.raises(KeyError, match="RESP-9999"):
        service.get("RESP-9999")


def test_invalid_action_is_rejected() -> None:
    service = ResponseService(make_incident_service())

    with pytest.raises(TypeError, match="action"):
        service.recommend(
            "INC-0001",
            "disable-device",
            "Invalid action must not be accepted",
            "analyst",
        )
