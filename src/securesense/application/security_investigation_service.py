"""Orchestrate security investigations and correlate incidents."""

from collections.abc import Sequence
from dataclasses import dataclass

from securesense.application.response_service import ResponseService
from securesense.application.security_pipeline_service import (
    SecurityPipelineResult,
    SecurityPipelineService,
)
from securesense.domain.attack_paths.correlator import AttackPathCorrelator
from securesense.domain.attack_paths.models import AttackPath
from securesense.domain.incidents.models import Incident
from securesense.domain.response.models import ResponseAction, ResponseRecord
from securesense.domain.telemetry.models import NetworkEvent


@dataclass(frozen=True)
class CorrelatedIncidentPath:
    """A candidate attack path linked to its corresponding incidents."""

    path: AttackPath
    incidents: tuple[Incident, ...]


@dataclass(frozen=True)
class SecurityInvestigationResult:
    """Results from processing events and correlating their findings."""

    event_results: tuple[SecurityPipelineResult, ...]
    correlated_paths: tuple[CorrelatedIncidentPath, ...]


class SecurityInvestigationService:
    """Coordinate event analysis, incidents, and candidate attack paths."""

    def __init__(
        self,
        pipeline: SecurityPipelineService,
        correlator: AttackPathCorrelator,
        response_service: ResponseService | None = None,
    ) -> None:
        self._pipeline = pipeline
        self._correlator = correlator
        self._response_service = response_service

    def recommend_response(
        self,
        incident_id: str,
        action: ResponseAction,
        reason: str,
        actor: str,
    ) -> ResponseRecord:
        """Record an explicitly requested dry-run response recommendation."""
        if self._response_service is None:
            raise RuntimeError(
                "ResponseService is not configured for this investigator"
            )

        return self._response_service.recommend(
            incident_id=incident_id,
            action=action,
            reason=reason,
            actor=actor,
        )

    def investigate(
        self,
        events: Sequence[NetworkEvent],
    ) -> SecurityInvestigationResult:
        """Process events and link correlated findings to their incidents."""
        event_results = tuple(self._pipeline.process(event) for event in events)

        findings_by_identity = {}
        incidents_by_finding: dict[int, Incident] = {}

        for result in event_results:
            finding = result.detection.finding
            incident = result.incident

            if finding is None:
                continue

            findings_by_identity[id(finding)] = finding

            if incident is not None:
                incidents_by_finding[id(finding)] = incident

        paths = self._correlator.correlate(
            tuple(findings_by_identity.values())
        )

        correlated_paths = tuple(
            CorrelatedIncidentPath(
                path=path,
                incidents=tuple(
                    incidents_by_finding[id(finding)]
                    for finding in path.findings
                    if id(finding) in incidents_by_finding
                ),
            )
            for path in paths
        )

        return SecurityInvestigationResult(
            event_results=event_results,
            correlated_paths=correlated_paths,
        )
