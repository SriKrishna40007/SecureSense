"""SQLite persistence for network-event deduplication."""

import sqlite3
from pathlib import Path


class SQLiteEventRepository:
    """Persist event IDs to recognize MQTT redelivery across restarts."""

    def __init__(self, database_path: Path | str) -> None:
        self._database_path = str(database_path)

        if self._database_path != ":memory:":
            Path(self._database_path).parent.mkdir(
                parents=True,
                exist_ok=True,
            )

        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS processed_network_events (
                    event_id TEXT PRIMARY KEY,
                    processed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self._database_path, timeout=10.0)
        connection.row_factory = sqlite3.Row
        return connection

    def claim(self, event_id: str) -> bool:
        """Atomically claim an event ID; return False if it already exists."""
        if not isinstance(event_id, str) or not event_id.strip():
            raise ValueError("'event_id' must be a non-empty string")

        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                """
                INSERT OR IGNORE INTO processed_network_events (event_id)
                VALUES (?)
                """,
                (event_id.strip(),),
            )
            connection.commit()
            return cursor.rowcount == 1
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def contains(self, event_id: str) -> bool:
        """Return whether an event ID has already been claimed."""
        connection = self._connect()
        try:
            row = connection.execute(
                """
                SELECT 1 FROM processed_network_events WHERE event_id = ?
                """,
                (event_id,),
            ).fetchone()
            return row is not None
        finally:
            connection.close()
