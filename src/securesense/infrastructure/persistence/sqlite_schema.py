"""Shared SQLite schema-version validation."""

import sqlite3

CURRENT_SCHEMA_VERSION = 3


def validate_schema_version(connection: sqlite3.Connection) -> None:
    """Reject databases whose schema is newer than this application supports."""
    version = connection.execute("PRAGMA user_version").fetchone()[0]

    if version > CURRENT_SCHEMA_VERSION:
        raise RuntimeError(
            f"Database schema version {version} is newer than the "
            f"supported version {CURRENT_SCHEMA_VERSION}"
        )


def mark_schema_current(connection: sqlite3.Connection) -> None:
    """Mark an initialized database with the current schema version."""
    connection.execute(f"PRAGMA user_version = {CURRENT_SCHEMA_VERSION}")
