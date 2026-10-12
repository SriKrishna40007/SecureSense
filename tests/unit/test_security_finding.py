from datetime import UTC, datetime

import pytest

from securesense.domain.findings.models import (
    FindingSeverity,
    SecurityFinding,
)


def make_finding(**overrides) -> SecurityFinding:
    values = {
        "rule_id": "NET-001",
        "title": "Unauthorized network communication",
        "severity": FindingSeverity.HIGH,
        "device_id": "TEMP-001",
        "description": "The device attempted unapproved network communication.",
        "evidence": {
            "protocol": "tcp",
            "destination": "unknown-host",
            "destination_port": 4444,
            "policy_reason": "Port '4444' is not allowed",
        },
        "recommendation": (
            "Verify the destination and review the device communication policy."
        ),
        "observed_at": datetime.now(UTC),
    }
    values.update(overrides)
    return SecurityFinding(**values)


def test_finding_preserves_security_evidence() -> None:
    finding = make_finding()

    assert finding.rule_id == "NET-001"
    assert finding.severity is FindingSeverity.HIGH
    assert finding.device_id == "TEMP-001"
    assert finding.evidence["destination_port"] == 4444
    assert finding.observed_at.tzinfo is not None


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("rule_id", ""),
        ("title", ""),
        ("device_id", ""),
        ("description", ""),
        ("recommendation", ""),
    ],
)
def test_finding_rejects_empty_required_text(
    field: str,
    value: str,
) -> None:
    with pytest.raises(ValueError):
        make_finding(**{field: value})


def test_finding_rejects_naive_timestamp() -> None:
    with pytest.raises(ValueError, match="timezone"):
        make_finding(observed_at=datetime.fromisoformat("2026-01-01T00:00:00"))


def test_finding_evidence_is_immutable() -> None:
    finding = make_finding()

    with pytest.raises(TypeError):
        finding.evidence["destination_port"] = 8883
