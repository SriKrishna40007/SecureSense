from datetime import UTC, datetime

import pytest

from securesense.domain.findings.models import (
    FindingSeverity,
    SecurityFinding,
)
from securesense.domain.risk.scorer import RiskBand, RiskScorer


@pytest.fixture
def finding_factory():
    def make_finding(severity: FindingSeverity) -> SecurityFinding:
        return SecurityFinding(
            rule_id="NET-001",
            title="Unauthorized network communication",
            severity=severity,
            device_id="TEMP-001",
            description="Observed communication violates device policy.",
            evidence={
                "protocol": "tcp",
                "destination": "unknown-host",
                "destination_port": 4444,
            },
            recommendation="Investigate the destination and review policy.",
            observed_at=datetime(2026, 10, 10, tzinfo=UTC),
        )

    return make_finding


@pytest.mark.parametrize(
    ("severity", "expected_score", "expected_band"),
    [
        (FindingSeverity.LOW, 20, RiskBand.LOW),
        (FindingSeverity.MEDIUM, 45, RiskBand.MEDIUM),
        (FindingSeverity.HIGH, 70, RiskBand.HIGH),
        (FindingSeverity.CRITICAL, 90, RiskBand.CRITICAL),
    ],
)
def test_scores_findings_by_severity(
    finding_factory,
    severity: FindingSeverity,
    expected_score: int,
    expected_band: RiskBand,
) -> None:
    assessment = RiskScorer().assess(finding_factory(severity))

    assert assessment.score == expected_score
    assert assessment.band is expected_band


def test_assessment_preserves_finding_identity(
    finding_factory,
) -> None:
    finding = finding_factory(FindingSeverity.HIGH)

    assessment = RiskScorer().assess(finding)

    assert assessment.rule_id == finding.rule_id
    assert assessment.device_id == finding.device_id
    assert assessment.observed_at == finding.observed_at


def test_assessment_explains_its_score(finding_factory) -> None:
    assessment = RiskScorer().assess(
        finding_factory(FindingSeverity.HIGH)
    )

    assert assessment.rationale
    assert "high" in assessment.rationale.lower()
    assert "70" in assessment.rationale
