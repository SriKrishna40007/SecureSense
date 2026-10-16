"""Tests for durable SQLite incident storage."""

import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from securesense.domain.incidents.models import Incident, IncidentStatus
from securesense.infrastructure.persistence.sqlite_incident_repository import (
    SQLiteIncidentRepository,
)


def make_incident() -> Incident:
    created_at = datetime(2026, 10, 12, 10, 0, tzinfo=UTC)
    return Incident(
        incident_id="INC-0001",
        title="Unauthorized IoT network communication",
        device_id="TEMP-001",
        risk_score=70,
        created_at=created_at,
        updated_at=created_at,
    )


def test_incident_survives_repository_reopen(tmp_path: Path) -> None:
    database = tmp_path / "securesense.sqlite3"
    incident = make_incident()

    SQLiteIncidentRepository(database).save(incident)

    restored = SQLiteIncidentRepository(database).get("INC-0001")

    assert restored.incident_id == incident.incident_id
    assert restored.title == incident.title
    assert restored.device_id == incident.device_id
    assert restored.risk_score == incident.risk_score
    assert restored.status is IncidentStatus.OPEN
    assert restored.created_at == incident.created_at
    assert restored.history == []


def test_lifecycle_audit_history_survives_repository_reopen(
    tmp_path: Path,
) -> None:
    database = tmp_path / "securesense.sqlite3"
    incident = make_incident()
    transition_time = incident.created_at + timedelta(minutes=5)

    incident.transition_to(
        new_status=IncidentStatus.INVESTIGATING,
        actor="security-analyst",
        note="Reviewing the unexpected destination",
        at=transition_time,
    )
    SQLiteIncidentRepository(database).save(incident)

    restored = SQLiteIncidentRepository(database).get("INC-0001")

    assert restored.status is IncidentStatus.INVESTIGATING
    assert restored.updated_at == transition_time
    assert len(restored.history) == 1
    assert restored.history[0].previous_status is IncidentStatus.OPEN
    assert restored.history[0].new_status is IncidentStatus.INVESTIGATING
    assert restored.history[0].actor == "security-analyst"
    assert restored.history[0].note == "Reviewing the unexpected destination"
    assert restored.history[0].occurred_at == transition_time


def test_id_sequence_survives_repository_reopen(tmp_path: Path) -> None:
    database = tmp_path / "securesense.sqlite3"

    first_repository = SQLiteIncidentRepository(database)
    first_id = first_repository.next_incident_id()

    second_repository = SQLiteIncidentRepository(database)
    second_id = second_repository.next_incident_id()

    assert first_id == "INC-0001"
    assert second_id == "INC-0002"


def test_list_all_restores_incidents_in_creation_order(
    tmp_path: Path,
) -> None:
    database = tmp_path / "securesense.sqlite3"
    repository = SQLiteIncidentRepository(database)
    first = make_incident()
    second_time = first.created_at + timedelta(minutes=1)
    second = Incident(
        incident_id="INC-0002",
        title="Unknown device detected",
        device_id="UNKNOWN-001",
        risk_score=60,
        created_at=second_time,
        updated_at=second_time,
    )

    repository.save(first)
    repository.save(second)

    restored = SQLiteIncidentRepository(database).list_all()

    assert [item.incident_id for item in restored] == [
        "INC-0001",
        "INC-0002",
    ]


def test_missing_incident_raises_key_error(tmp_path: Path) -> None:
    repository = SQLiteIncidentRepository(tmp_path / "securesense.sqlite3")

    try:
        repository.get("INC-9999")
    except KeyError as exc:
        assert "INC-9999" in str(exc)
    else:
        raise AssertionError("Expected missing incident to raise KeyError")


def test_failed_audit_write_rolls_back_incident_update(
    tmp_path: Path,
) -> None:
    database = tmp_path / "securesense.sqlite3"
    repository = SQLiteIncidentRepository(database)
    incident = make_incident()
    repository.save(incident)

    incident.transition_to(
        new_status=IncidentStatus.INVESTIGATING,
        actor="security-analyst",
        note="Investigating a suspicious connection",
        at=incident.created_at + timedelta(minutes=5),
    )

    with sqlite3.connect(database) as connection:
        connection.execute(
            """
            CREATE TRIGGER reject_audit_insert
            BEFORE INSERT ON incident_audit_entries
            BEGIN
                SELECT RAISE(ABORT, 'simulated audit write failure');
            END
            """
        )

    with pytest.raises(sqlite3.IntegrityError, match="simulated audit write failure"):
        repository.save(incident)

    restored = SQLiteIncidentRepository(database).get("INC-0001")
    assert restored.status is IncidentStatus.OPEN
    assert restored.history == []
