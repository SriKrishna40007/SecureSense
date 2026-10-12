"""Human-readable security investigation reports."""

from collections import Counter
from collections.abc import Sequence

from securesense.application.security_investigation_service import (
    SecurityInvestigationResult,
)
from securesense.domain.response.models import ResponseRecord


class InvestigationReportFormatter:
    """Format investigation results without executing response actions."""

    def format(
        self,
        result: SecurityInvestigationResult,
        responses: Sequence[ResponseRecord] = (),
    ) -> str:
        """Return an evidence-backed, human-readable investigation report."""
        if not isinstance(result, SecurityInvestigationResult):
            raise TypeError("'result' must be a SecurityInvestigationResult")

        if isinstance(responses, (str, bytes)):
            raise TypeError("'responses' must be a sequence of ResponseRecord")

        if any(not isinstance(item, ResponseRecord) for item in responses):
            raise TypeError("All responses must be ResponseRecord instances")

        findings = [
            event_result.detection.finding
            for event_result in result.event_results
            if event_result.detection.finding is not None
        ]
        incidents = [
            event_result.incident
            for event_result in result.event_results
            if event_result.incident is not None
        ]
        risk_assessments = [
            event_result.risk_assessment
            for event_result in result.event_results
            if event_result.risk_assessment is not None
        ]

        severity_counts = Counter(
            finding.severity.value for finding in findings
        )

        lines = [
            "SECURESENSE INVESTIGATION REPORT",
            "=" * 36,
            "",
            "EXECUTIVE SUMMARY",
            f"Events investigated: {len(result.event_results)}",
            f"Findings: {len(findings)}",
            f"Incidents: {len(incidents)}",
            f"Candidate attack paths: {len(result.correlated_paths)}",
            "Severity counts: "
            + (
                ", ".join(
                    f"{severity}={severity_counts[severity]}"
                    for severity in ("critical", "high", "medium", "low")
                    if severity_counts[severity]
                )
                or "none"
            ),
            "",
            "FINDINGS AND EVIDENCE",
        ]

        if not findings:
            lines.append("No security findings were produced.")
        else:
            for index, finding in enumerate(findings, start=1):
                lines.extend(
                    [
                        "",
                        f"{index}. {finding.rule_id} — {finding.title}",
                        f"   Severity: {finding.severity.value}",
                        f"   Device: {finding.device_id}",
                        f"   Observed: {finding.observed_at.isoformat()}",
                        f"   Description: {finding.description}",
                        "   Evidence:",
                    ]
                )

                for key, value in sorted(finding.evidence.items()):
                    lines.append(f"     - {key}: {value!s}")

                lines.append(
                    f"   Recommendation: {finding.recommendation}"
                )

        lines.extend(["", "RISK ASSESSMENTS"])

        if not risk_assessments:
            lines.append("No risk assessments were produced.")
        else:
            for assessment in risk_assessments:
                lines.extend(
                    [
                        f"- {assessment.rule_id} / {assessment.device_id}",
                        f"  Risk score: {assessment.score}/100",
                        f"  Risk band: {assessment.band.value}",
                        f"  Rationale: {assessment.rationale}",
                    ]
                )

        lines.extend(["", "INCIDENTS AND LIFECYCLE"])

        if not incidents:
            lines.append("No incidents were created.")
        else:
            for incident in incidents:
                lines.extend(
                    [
                        f"- {incident.incident_id}: {incident.title}",
                        f"  Device: {incident.device_id}",
                        f"  Status: {incident.status.value}",
                        f"  Risk score: {incident.risk_score}/100",
                        f"  Created: {incident.created_at.isoformat()}",
                        f"  Updated: {incident.updated_at.isoformat()}",
                    ]
                )

                if incident.history:
                    lines.append("  Audit history:")

                    for entry in incident.history:
                        lines.append(
                            f"    - {entry.occurred_at.isoformat()}: "
                            f"{entry.previous_status.value} -> "
                            f"{entry.new_status.value}; "
                            f"actor={entry.actor}; note={entry.note}"
                        )
                else:
                    lines.append("  Audit history: no status transitions")

        lines.extend(["", "CANDIDATE ATTACK PATHS"])

        if not result.correlated_paths:
            lines.append("No candidate paths were correlated.")
        else:
            lines.append(
                "These are correlations requiring analyst validation, "
                "not proof of an attack."
            )

            for index, linked in enumerate(result.correlated_paths, start=1):
                path = linked.path
                observed_window = (
                    f"  Observed window: "
                    f"{path.observed_start.isoformat()} to "
                    f"{path.observed_end.isoformat()}"
                )
                linked_incidents = ", ".join(
                    incident.incident_id for incident in linked.incidents
                ) or "none"

                lines.extend(
                    [
                        f"- Candidate path {index}",
                        observed_window,
                        f"  Shared IP evidence: {', '.join(path.shared_ips)}",
                        f"  Rationale: {path.rationale}",
                        f"  Linked incidents: {linked_incidents}",
                    ]
                )

        lines.extend(["", "RESPONSE AUDIT"])

        if not responses:
            lines.append("No response recommendations recorded.")
        else:
            for response in responses:
                lines.extend(
                    [
                        f"- {response.response_id} / {response.incident_id}",
                        "  Status: DRY RUN — NOT EXECUTED",
                        f"  Action: {response.action.value}",
                        f"  Device: {response.device_id}",
                        f"  Reason: {response.reason}",
                        f"  Actor: {response.actor}",
                        f"  Recorded: {response.created_at.isoformat()}",
                        f"  Executed: {str(response.executed).lower()}",
                    ]
                )

        lines.extend(
            [
                "",
                "REPORT LIMITATIONS",
                "- Risk scores use SecureSense's configured severity-based rules.",
                "- Candidate attack paths are correlations, not confirmed attribution.",
                "- Response recommendations do not change device or network state.",
            ]
        )

        return "\n".join(lines)
