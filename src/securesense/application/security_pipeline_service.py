"""Orchestrate network-event detection, risk assessment, and incidents."""

from dataclasses import dataclass

from securesense.application.incident_service import IncidentService
from securesense.application.security_detection_service import (
    DetectionResult,
    SecurityDetectionService,
)
from securesense.domain.incidents.models import Incident
from securesense.domain.risk.scorer import RiskAssessment, RiskScorer
from securesense.domain.telemetry.models import NetworkEvent


@dataclass(frozen=True)
class SecurityPipelineResult:
    """Capture the output of processing one network event."""

    detection: DetectionResult
    risk_assessment: RiskAssessment | None
    incident: Incident | None
    duplicate_event: bool = False


class SecurityPipelineService:
    """Connect detection to risk scoring and incident creation."""

    def __init__(
        self,
        detector: SecurityDetectionService,
        risk_scorer: RiskScorer,
        incident_service: IncidentService,
    ) -> None:
        self._detector = detector
        self._risk_scorer = risk_scorer
        self.incidents = incident_service

    def process(self, event: NetworkEvent) -> SecurityPipelineResult:
        """Process an event and create an incident for detected violations."""
        detection = self._detector.evaluate(event)

        if detection.finding is None:
            duplicate_event = False
            if event.event_id is not None:
                duplicate_event = not self.incidents.record_event_id(
                    event.event_id
                )
            return SecurityPipelineResult(
                detection=detection,
                risk_assessment=None,
                incident=None,
                duplicate_event=duplicate_event,
            )

        assessment = self._risk_scorer.assess(detection.finding)
        if event.event_id is not None:
            accepted, incident = self.incidents.create_from_finding_for_event(
                event.event_id,
                detection.finding,
                assessment,
            )
            return SecurityPipelineResult(
                detection=detection,
                risk_assessment=assessment,
                incident=incident,
                duplicate_event=not accepted,
            )

        incident = self.incidents.create_from_finding(
            detection.finding,
            assessment,
        )
        return SecurityPipelineResult(
            detection=detection,
            risk_assessment=assessment,
            incident=incident,
        )
