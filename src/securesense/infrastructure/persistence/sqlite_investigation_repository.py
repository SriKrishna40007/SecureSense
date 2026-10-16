"""SQLite persistence for security investigation requests and results."""

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from securesense.infrastructure.persistence.sqlite_schema import (
    mark_schema_current,
    validate_schema_version,
)


class SQLiteInvestigationRepository:
    """Store completed investigation records for later retrieval."""

    def __init__(self, database_path: Path | str) -> None:
        self._database_path = str(database_path)

        if self._database_path != ":memory:":
            Path(self._database_path).parent.mkdir(
                parents=True,
                exist_ok=True,
            )

        with self._connect() as connection:
            validate_schema_version(connection)
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS investigations (
                    investigation_id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    events_json TEXT NOT NULL,
                    result_json TEXT NOT NULL
                )
                """
            )
            mark_schema_current(connection)

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        """Open and always close a database connection."""
        connection = sqlite3.connect(
            self._database_path,
            timeout=10.0,
        )
        connection.row_factory = sqlite3.Row
        try:
            yield connection
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def save(
        self,
        investigation_id: str,
        events: list[dict[str, Any]],
        result: dict[str, Any],
    ) -> dict[str, Any]:
        """Persist an investigation and return its stored representation."""
        if not isinstance(investigation_id, str) or not investigation_id.strip():
            raise ValueError("'investigation_id' must not be empty")

        if not isinstance(events, list):
            raise TypeError("'events' must be a list")

        if not isinstance(result, dict):
            raise TypeError("'result' must be a dictionary")

        created_at = datetime.now(UTC).isoformat()
        events_json = json.dumps(
            events,
            sort_keys=True,
            separators=(",", ":"),
        )
        result_json = json.dumps(
            result,
            sort_keys=True,
            separators=(",", ":"),
        )

        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO investigations (
                    investigation_id,
                    created_at,
                    events_json,
                    result_json
                ) VALUES (?, ?, ?, ?)
                """,
                (
                    investigation_id,
                    created_at,
                    events_json,
                    result_json,
                ),
            )

        return {
            "investigation_id": investigation_id,
            "created_at": created_at,
            "events": json.loads(events_json),
            "result": json.loads(result_json),
        }

    def get(self, investigation_id: str) -> dict[str, Any]:
        """Retrieve a previously stored investigation."""
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT investigation_id, created_at, events_json, result_json
                FROM investigations
                WHERE investigation_id = ?
                """,
                (investigation_id,),
            ).fetchone()

        if row is None:
            raise KeyError(f"Investigation '{investigation_id}' was not found")

        return {
            "investigation_id": row["investigation_id"],
            "created_at": row["created_at"],
            "events": json.loads(row["events_json"]),
            "result": json.loads(row["result_json"]),
        }

    def list_all(self) -> list[dict[str, Any]]:
        """List saved investigations in creation order."""
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT investigation_id
                FROM investigations
                ORDER BY created_at, investigation_id
                """
            ).fetchall()

        return [self.get(row["investigation_id"]) for row in rows]
