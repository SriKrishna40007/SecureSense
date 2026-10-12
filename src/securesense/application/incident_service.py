"""Application service for creating and retrieving security incidents."""

from datetime import UTC, datetime

from securesense.domain.findings.models import SecurityFinding
from securesense.domain.incidents.models import Incident
from securesense.domain.risk.scorer import RiskAssessment


class IncidentService:
    """Manage in-memory incidents created from security findings."""

    def __init__(self) -> None:
        self._incidents: dict[str, Incident] = {}
        self._next_id = 1

    def create_from_finding(
        self,
        finding: SecurityFinding,
        assessment: RiskAssessment,
    ) -> Incident:
        """Create an incident after validating its finding and assessment."""
        if not isinstance(finding, SecurityFinding):
            raise TypeError("'finding' must be a SecurityFinding")

        if not isinstance(assessment, RiskAssessment):
            raise TypeError("'assessment' must be a RiskAssessment")

        if (
            assessment.rule_id != finding.rule_id
            or assessment.device_id != finding.device_id
            or assessment.observed_at != finding.observed_at
        ):
            raise ValueError(
                "Risk assessment does not match the security finding"
            )

        incident_id = f"INC-{self._next_id:04d}"
        now = datetime.now(UTC)

        incident = Incident(
            incident_id=incident_id,
            title=finding.title,
            device_id=finding.device_id,
            risk_score=assessment.score,
            created_at=now,
            updated_at=now,
        )

        self._incidents[incident_id] = incident
        self._next_id += 1
        return incident

    def get(self, incident_id: str) -> Incident:
        """Retrieve an incident by ID."""
        try:
            return self._incidents[incident_id]
        except KeyError:
            raise KeyError(f"Incident '{incident_id}' was not found") from None

    def list_incidents(self) -> list[Incident]:
        """Return incidents in creation order."""
        return list(self._incidents.values())
