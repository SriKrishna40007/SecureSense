"""Application service for creating and retrieving security incidents."""

from datetime import UTC, datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from securesense.infrastructure.persistence.sqlite_incident_repository import (
        SQLiteIncidentRepository,
    )

from securesense.domain.findings.models import SecurityFinding
from securesense.domain.incidents.models import Incident, IncidentStatus
from securesense.domain.risk.scorer import RiskAssessment


class IncidentService:
    """Manage incidents using memory or a durable repository."""

    def __init__(
        self,
        repository: "SQLiteIncidentRepository | None" = None,
    ) -> None:
        self._repository = repository
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
            raise ValueError("Risk assessment does not match the security finding")

        incident_id = (
            self._repository.next_incident_id()
            if self._repository is not None
            else f"INC-{self._next_id:04d}"
        )
        now = datetime.now(UTC)

        incident = Incident(
            incident_id=incident_id,
            title=finding.title,
            device_id=finding.device_id,
            risk_score=assessment.score,
            created_at=now,
            updated_at=now,
        )

        if self._repository is not None:
            self._repository.save(incident)
        else:
            self._incidents[incident_id] = incident
            self._next_id += 1
        return incident

    def get(self, incident_id: str) -> Incident:
        """Retrieve an incident by ID."""
        if self._repository is not None:
            return self._repository.get(incident_id)
        try:
            return self._incidents[incident_id]
        except KeyError:
            raise KeyError(f"Incident '{incident_id}' was not found") from None

    def transition(
        self,
        incident_id: str,
        new_status: IncidentStatus,
        actor: str,
        note: str,
        at: datetime | None = None,
    ) -> Incident:
        """Transition an incident and persist its updated audit history."""
        incident = self.get(incident_id)
        incident.transition_to(
            new_status=new_status,
            actor=actor,
            note=note,
            at=at if at is not None else datetime.now(UTC),
        )

        if self._repository is not None:
            self._repository.save(incident)

        return incident

    def list_incidents(self) -> list[Incident]:
        """Return incidents in creation order."""
        if self._repository is not None:
            return self._repository.list_all()
        return list(self._incidents.values())
