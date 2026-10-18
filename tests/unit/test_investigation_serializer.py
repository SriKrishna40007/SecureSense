from types import SimpleNamespace

from securesense.api.investigation_serializer import (
    serialize_investigation_result,
)


def test_serializer_exposes_duplicate_event_flag() -> None:
    result = SimpleNamespace(
        event_results=(
            SimpleNamespace(
                detection=SimpleNamespace(
                    decision=SimpleNamespace(
                        allowed=False,
                        reason="Duplicate event",
                    ),
                    finding=None,
                ),
                risk_assessment=None,
                incident=None,
                duplicate_event=True,
            ),
        ),
        correlated_paths=(),
    )

    serialized = serialize_investigation_result(result)

    assert serialized["event_results"][0]["duplicate_event"] is True
