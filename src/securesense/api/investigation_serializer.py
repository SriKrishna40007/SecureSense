"""Convert investigation results into JSON-safe API records."""

from typing import Any


def serialize_investigation_result(result: Any) -> dict[str, Any]:
    """Serialize pipeline results without deep-copying immutable evidence."""
    event_results = []

    for event_result in result.event_results:
        finding = event_result.detection.finding
        assessment = event_result.risk_assessment
        incident = event_result.incident

        event_results.append(
            {
                "allowed": event_result.detection.decision.allowed,
                "decision_reason": event_result.detection.decision.reason,
                "duplicate_event": event_result.duplicate_event,
                "finding": (
                    {
                        "rule_id": finding.rule_id,
                        "title": finding.title,
                        "severity": finding.severity.value,
                        "device_id": finding.device_id,
                        "description": finding.description,
                        "evidence": dict(finding.evidence),
                        "recommendation": finding.recommendation,
                        "observed_at": finding.observed_at.isoformat(),
                    }
                    if finding is not None
                    else None
                ),
                "risk_assessment": (
                    {
                        "score": assessment.score,
                        "band": assessment.band.value,
                        "rationale": assessment.rationale,
                    }
                    if assessment is not None
                    else None
                ),
                "incident": (
                    {
                        "incident_id": incident.incident_id,
                        "title": incident.title,
                        "device_id": incident.device_id,
                        "risk_score": incident.risk_score,
                        "status": incident.status.value,
                        "created_at": incident.created_at.isoformat(),
                    }
                    if incident is not None
                    else None
                ),
            }
        )

    candidate_paths = [
        {
            "classification": "candidate — requires analyst validation",
            "shared_ips": list(linked.path.shared_ips),
            "rationale": linked.path.rationale,
            "observed_start": linked.path.observed_start.isoformat(),
            "observed_end": linked.path.observed_end.isoformat(),
            "incident_ids": [
                incident.incident_id for incident in linked.incidents
            ],
        }
        for linked in result.correlated_paths
    ]

    return {
        "events_investigated": len(result.event_results),
        "findings_count": sum(
            item["finding"] is not None for item in event_results
        ),
        "incidents_count": sum(
            item["incident"] is not None for item in event_results
        ),
        "candidate_attack_paths_count": len(candidate_paths),
        "event_results": event_results,
        "candidate_attack_paths": candidate_paths,
        "response_execution": "No response actions were executed.",
    }
