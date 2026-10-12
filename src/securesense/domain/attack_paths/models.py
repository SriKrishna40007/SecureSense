"""Models for evidence-backed candidate attack paths."""

from dataclasses import dataclass
from datetime import datetime

from securesense.domain.findings.models import SecurityFinding


@dataclass(frozen=True)
class AttackPath:
    """A candidate path formed from chronologically linked findings."""

    findings: tuple[SecurityFinding, ...]
    shared_ips: tuple[str, ...]
    rationale: str
    observed_start: datetime
    observed_end: datetime

    def __post_init__(self) -> None:
        """Validate the path's evidence and chronological boundaries."""
        if len(self.findings) < 2:
            raise ValueError("An attack path requires at least two findings")

        if not self.shared_ips:
            raise ValueError("An attack path requires shared network evidence")

        if not self.rationale.strip():
            raise ValueError("'rationale' must not be empty")

        if self.observed_start > self.observed_end:
            raise ValueError("Path start must not be after its end")
