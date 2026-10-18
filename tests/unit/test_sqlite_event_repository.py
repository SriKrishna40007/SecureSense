"""Tests for persistent MQTT event-ID tracking."""

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from securesense.infrastructure.persistence.sqlite_event_repository import (
    SQLiteEventRepository,
)


def test_claims_event_id_only_once(tmp_path: Path) -> None:
    database = tmp_path / "events.sqlite3"
    repository = SQLiteEventRepository(database)

    assert repository.claim("event-001") is True
    assert repository.claim("event-001") is False
    assert repository.contains("event-001") is True


def test_event_id_survives_repository_reopen(tmp_path: Path) -> None:
    database = tmp_path / "events.sqlite3"

    assert SQLiteEventRepository(database).claim("event-001") is True
    reopened = SQLiteEventRepository(database)

    assert reopened.contains("event-001") is True
    assert reopened.claim("event-001") is False


def test_distinct_event_ids_are_independent(tmp_path: Path) -> None:
    repository = SQLiteEventRepository(tmp_path / "events.sqlite3")

    assert repository.claim("event-001") is True
    assert repository.claim("event-002") is True


def test_concurrent_claims_only_succeed_once(tmp_path: Path) -> None:
    repository = SQLiteEventRepository(tmp_path / "events.sqlite3")

    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(repository.claim, ["event-001"] * 8))

    assert results.count(True) == 1
    assert results.count(False) == 7
