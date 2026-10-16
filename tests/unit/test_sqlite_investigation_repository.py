"""Tests for durable investigation history."""

import sqlite3
from pathlib import Path

import pytest

from securesense.infrastructure.persistence.sqlite_investigation_repository import (
    SQLiteInvestigationRepository,
)


def test_investigation_survives_repository_reopen(
    tmp_path: Path,
) -> None:
    database = tmp_path / "securesense.sqlite3"
    events = [
        {
            "device_id": "TEMP-001",
            "protocol": "tcp",
            "destination_port": 443,
        }
    ]
    result = {
        "findings_count": 1,
        "event_results": [{"incident": {"incident_id": "INC-0001", "status": "open"}}],
    }

    SQLiteInvestigationRepository(database).save(
        "INV-test-001",
        events,
        result,
    )

    restored = SQLiteInvestigationRepository(database).get("INV-test-001")

    assert restored["investigation_id"] == "INV-test-001"
    assert restored["events"] == events
    assert restored["result"] == result
    assert restored["created_at"]


def test_lists_investigations(tmp_path: Path) -> None:
    database = tmp_path / "securesense.sqlite3"
    repository = SQLiteInvestigationRepository(database)

    repository.save("INV-001", [], {"findings_count": 0})
    repository.save("INV-002", [], {"findings_count": 1})

    restored = SQLiteInvestigationRepository(database).list_all()

    assert [item["investigation_id"] for item in restored] == [
        "INV-001",
        "INV-002",
    ]


def test_missing_investigation_raises_key_error(
    tmp_path: Path,
) -> None:
    repository = SQLiteInvestigationRepository(tmp_path / "securesense.sqlite3")

    with pytest.raises(KeyError, match="INV-missing"):
        repository.get("INV-missing")


def test_duplicate_investigation_id_is_rejected(
    tmp_path: Path,
) -> None:
    repository = SQLiteInvestigationRepository(tmp_path / "securesense.sqlite3")
    repository.save("INV-001", [], {"findings_count": 0})

    with pytest.raises(sqlite3.IntegrityError):
        repository.save("INV-001", [], {"findings_count": 1})
