"""Tests for shared SQLite schema versioning."""

import sqlite3
from pathlib import Path

import pytest

from securesense.infrastructure.persistence.sqlite_incident_repository import (
    SQLiteIncidentRepository,
)
from securesense.infrastructure.persistence.sqlite_investigation_repository import (
    SQLiteInvestigationRepository,
)


def get_schema_version(database: Path) -> int:
    with sqlite3.connect(database) as connection:
        return connection.execute("PRAGMA user_version").fetchone()[0]


def get_table_names(database: Path) -> set[str]:
    with sqlite3.connect(database) as connection:
        rows = connection.execute(
            """
            SELECT name
            FROM sqlite_master
            WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
            """
        ).fetchall()
    return {row[0] for row in rows}


def test_both_repositories_share_schema_version(tmp_path: Path) -> None:
    database = tmp_path / "shared.sqlite3"

    SQLiteIncidentRepository(database)
    SQLiteInvestigationRepository(database)

    assert get_schema_version(database) == 3
    assert {
        "incidents",
        "incident_audit_entries",
        "id_sequences",
        "investigations",
    } <= get_table_names(database)


def test_legacy_database_data_is_preserved(tmp_path: Path) -> None:
    database = tmp_path / "legacy.sqlite3"

    with sqlite3.connect(database) as connection:
        connection.execute("CREATE TABLE legacy_marker (marker TEXT NOT NULL)")
        connection.execute("INSERT INTO legacy_marker VALUES ('preserve-me')")

    SQLiteIncidentRepository(database)

    with sqlite3.connect(database) as connection:
        marker = connection.execute("SELECT marker FROM legacy_marker").fetchone()[0]

    assert marker == "preserve-me"
    assert get_schema_version(database) == 3


@pytest.mark.parametrize(
    "repository_type",
    [SQLiteIncidentRepository, SQLiteInvestigationRepository],
)
def test_future_schema_is_rejected_without_creating_tables(
    tmp_path: Path,
    repository_type: type,
) -> None:
    database = tmp_path / f"{repository_type.__name__}.sqlite3"

    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA user_version = 999")

    with pytest.raises(RuntimeError, match="newer than the supported version"):
        repository_type(database)

    assert get_schema_version(database) == 999
    assert get_table_names(database) == set()
