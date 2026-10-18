"""SQLite persistence for security incidents and their audit history."""

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

from securesense.domain.incidents.models import (
    Incident,
    IncidentAuditEntry,
    IncidentStatus,
)
from securesense.infrastructure.persistence.sqlite_schema import (
    mark_schema_current,
    validate_schema_version,
)


class SQLiteIncidentRepository:
    """Persist incidents and lifecycle history in a local SQLite database."""

    def __init__(self, database_path: Path | str) -> None:
        self._database_path = str(database_path)

        if self._database_path != ":memory:":
            Path(self._database_path).parent.mkdir(
                parents=True,
                exist_ok=True,
            )

        with self._connect() as connection:
            validate_schema_version(connection)
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS incidents (
                    incident_id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    device_id TEXT NOT NULL,
                    risk_score INTEGER NOT NULL
                        CHECK (risk_score BETWEEN 0 AND 100),
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    status TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS incident_audit_entries (
                    incident_id TEXT NOT NULL,
                    sequence INTEGER NOT NULL,
                    previous_status TEXT NOT NULL,
                    new_status TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    note TEXT NOT NULL,
                    occurred_at TEXT NOT NULL,
                    PRIMARY KEY (incident_id, sequence),
                    FOREIGN KEY (incident_id)
                        REFERENCES incidents (incident_id)
                        ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS id_sequences (
                    sequence_name TEXT PRIMARY KEY,
                    next_value INTEGER NOT NULL CHECK (next_value > 0)
                );

                CREATE TABLE IF NOT EXISTS processed_network_events (
                    event_id TEXT PRIMARY KEY,
                    processed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );

                INSERT OR IGNORE INTO id_sequences (
                    sequence_name,
                    next_value
                ) VALUES ('incident', 1);
                """
            )
            mark_schema_current(connection)

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        """Open and always close a connection with foreign keys enabled."""
        connection = sqlite3.connect(
            self._database_path,
            timeout=10.0,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        try:
            yield connection
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def next_incident_id(self) -> str:
        """Allocate a unique incident ID using a database transaction."""
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """
                SELECT next_value
                FROM id_sequences
                WHERE sequence_name = 'incident'
                """
            ).fetchone()

            if row is None:
                raise RuntimeError("Incident ID sequence is missing")

            number = row["next_value"]
            connection.execute(
                """
                UPDATE id_sequences
                SET next_value = ?
                WHERE sequence_name = 'incident'
                """,
                (number + 1,),
            )

        return f"INC-{number:04d}"

    def save(self, incident: Incident) -> None:
        """Insert or update an incident and replace its audit history."""
        if not isinstance(incident, Incident):
            raise TypeError("'incident' must be an Incident")

        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """
                INSERT INTO incidents (
                    incident_id, title, device_id, risk_score,
                    created_at, updated_at, status
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(incident_id) DO UPDATE SET
                    title = excluded.title,
                    device_id = excluded.device_id,
                    risk_score = excluded.risk_score,
                    created_at = excluded.created_at,
                    updated_at = excluded.updated_at,
                    status = excluded.status
                """,
                (
                    incident.incident_id,
                    incident.title,
                    incident.device_id,
                    incident.risk_score,
                    incident.created_at.isoformat(),
                    incident.updated_at.isoformat(),
                    incident.status.value,
                ),
            )

            connection.execute(
                """
                DELETE FROM incident_audit_entries
                WHERE incident_id = ?
                """,
                (incident.incident_id,),
            )

            connection.executemany(
                """
                INSERT INTO incident_audit_entries (
                    incident_id, sequence, previous_status,
                    new_status, actor, note, occurred_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        incident.incident_id,
                        sequence,
                        entry.previous_status.value,
                        entry.new_status.value,
                        entry.actor,
                        entry.note,
                        entry.occurred_at.isoformat(),
                    )
                    for sequence, entry in enumerate(incident.history, start=1)
                ],
            )


    def record_event(self, event_id: str) -> bool:
        """Atomically record an event ID; return False for a duplicate."""
        if not isinstance(event_id, str) or not event_id.strip():
            raise ValueError("'event_id' must be a non-empty string")

        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                """
                INSERT OR IGNORE INTO processed_network_events (event_id)
                VALUES (?)
                """,
                (event_id.strip(),),
            )
            return cursor.rowcount == 1

    def save_event_and_incident(
        self,
        event_id: str,
        incident: Incident | None,
    ) -> bool:
        """Record an event and optional incident in one transaction.

        Returns False if the event ID was already processed. Any incident
        persistence failure rolls back the event record as well.
        """
        if not isinstance(event_id, str) or not event_id.strip():
            raise ValueError("'event_id' must be a non-empty string")
        if incident is not None and not isinstance(incident, Incident):
            raise TypeError("'incident' must be an Incident or None")

        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                """
                INSERT OR IGNORE INTO processed_network_events (event_id)
                VALUES (?)
                """,
                (event_id.strip(),),
            )
            if cursor.rowcount == 0:
                return False

            if incident is None:
                return True

            connection.execute(
                """
                INSERT INTO incidents (
                    incident_id, title, device_id, risk_score,
                    created_at, updated_at, status
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    incident.incident_id,
                    incident.title,
                    incident.device_id,
                    incident.risk_score,
                    incident.created_at.isoformat(),
                    incident.updated_at.isoformat(),
                    incident.status.value,
                ),
            )
            connection.executemany(
                """
                INSERT INTO incident_audit_entries (
                    incident_id, sequence, previous_status,
                    new_status, actor, note, occurred_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        incident.incident_id,
                        sequence,
                        entry.previous_status.value,
                        entry.new_status.value,
                        entry.actor,
                        entry.note,
                        entry.occurred_at.isoformat(),
                    )
                    for sequence, entry in enumerate(incident.history, start=1)
                ],
            )
            return True

    def get(self, incident_id: str) -> Incident:
        """Load an incident and its ordered audit history."""
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM incidents WHERE incident_id = ?",
                (incident_id,),
            ).fetchone()

            if row is None:
                raise KeyError(f"Incident '{incident_id}' was not found")

            audit_rows = connection.execute(
                """
                SELECT *
                FROM incident_audit_entries
                WHERE incident_id = ?
                ORDER BY sequence
                """,
                (incident_id,),
            ).fetchall()

        history = [
            IncidentAuditEntry(
                previous_status=IncidentStatus(item["previous_status"]),
                new_status=IncidentStatus(item["new_status"]),
                actor=item["actor"],
                note=item["note"],
                occurred_at=datetime.fromisoformat(item["occurred_at"]),
            )
            for item in audit_rows
        ]

        return Incident(
            incident_id=row["incident_id"],
            title=row["title"],
            device_id=row["device_id"],
            risk_score=row["risk_score"],
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
            status=IncidentStatus(row["status"]),
            history=history,
        )

    def list_all(self) -> list[Incident]:
        """Load incidents in creation order, including their audit histories."""
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT incident_id FROM incidents ORDER BY created_at, incident_id"
            ).fetchall()

        return [self.get(row["incident_id"]) for row in rows]

    def close(self) -> None:
        """Compatibility hook; connections are scoped to individual operations."""
