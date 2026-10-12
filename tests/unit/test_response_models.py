from datetime import UTC, datetime

import pytest

from securesense.domain.response.models import (
    ResponseAction,
    ResponseExecutionMode,
    ResponseRecord,
)


def make_record(**overrides: object) -> ResponseRecord:
    values: dict[str, object] = {
        "response_id": "RESP-0001",
        "incident_id": "INC-0001",
        "device_id": "TEMP-001",
        "action": ResponseAction.RECOMMEND_CONTAINMENT,
        "mode": ResponseExecutionMode.DRY_RUN,
        "reason": "Repeated unauthorized network communication",
        "actor": "securesense",
        "created_at": datetime(2026, 10, 10, 8, 0, tzinfo=UTC),
        "executed": False,
    }
    values.update(overrides)
    return ResponseRecord(**values)  # type: ignore[arg-type]


def test_response_record_captures_auditable_dry_run() -> None:
    record = make_record()

    assert record.response_id == "RESP-0001"
    assert record.incident_id == "INC-0001"
    assert record.device_id == "TEMP-001"
    assert record.action is ResponseAction.RECOMMEND_CONTAINMENT
    assert record.mode is ResponseExecutionMode.DRY_RUN
    assert record.actor == "securesense"
    assert record.executed is False


def test_dry_run_cannot_be_recorded_as_executed() -> None:
    with pytest.raises(ValueError, match="Dry-run responses cannot be executed"):
        make_record(executed=True)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("response_id", ""),
        ("incident_id", ""),
        ("device_id", ""),
        ("reason", ""),
        ("actor", ""),
    ],
)
def test_response_record_rejects_empty_required_text(
    field: str,
    value: str,
) -> None:
    with pytest.raises(ValueError):
        make_record(**{field: value})


def test_response_record_rejects_naive_timestamp() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        make_record(created_at=datetime(2026, 10, 10, 8, 0))  # noqa: DTZ001


def test_response_record_rejects_unknown_action() -> None:
    with pytest.raises(TypeError, match="action"):
        make_record(action="disable-device")


def test_response_record_rejects_unknown_execution_mode() -> None:
    with pytest.raises(TypeError, match="mode"):
        make_record(mode="live")
