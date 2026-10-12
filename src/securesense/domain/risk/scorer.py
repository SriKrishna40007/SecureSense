"""Deterministic, explainable risk scoring for security findings."""

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import ClassVar

from securesense.domain.findings.models import (
    FindingSeverity,
    SecurityFinding,
)


class RiskBand(StrEnum):
    """Human-readable risk classification."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class RiskAssessment:
    """Explainable risk assessment linked to its source finding."""

    rule_id: str
    device_id: str
    score: int
    band: RiskBand
    rationale: str
    observed_at: datetime


class RiskScorer:
    """Score findings using a deterministic severity-based policy."""

    _SCORES: ClassVar[dict[FindingSeverity, int]] = {
        FindingSeverity.LOW: 20,
        FindingSeverity.MEDIUM: 45,
        FindingSeverity.HIGH: 70,
        FindingSeverity.CRITICAL: 90,
    }

    _BANDS: ClassVar[tuple[tuple[int, RiskBand], ...]] = (
        (25, RiskBand.LOW),
        (50, RiskBand.MEDIUM),
        (75, RiskBand.HIGH),
        (100, RiskBand.CRITICAL),
    )

    def assess(self, finding: SecurityFinding) -> RiskAssessment:
        """Return a reproducible risk score and its explanation."""
        if not isinstance(finding, SecurityFinding):
            raise TypeError("'finding' must be a SecurityFinding")

        score = self._SCORES[finding.severity]
        band = next(
            band
            for upper_bound, band in self._BANDS
            if score <= upper_bound
        )
        rationale = (
            f"Finding severity is {finding.severity.value}; "
            f"the configured severity-based score is {score}/100, "
            f"classified as {band.value} risk."
        )

        return RiskAssessment(
            rule_id=finding.rule_id,
            device_id=finding.device_id,
            score=score,
            band=band,
            rationale=rationale,
            observed_at=finding.observed_at,
        )
