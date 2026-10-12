"""Convert device policy decisions into evidence-backed findings."""

from dataclasses import dataclass

from securesense.application.device_security_service import (
    DeviceSecurityService,
)
from securesense.domain.findings.models import (
    FindingSeverity,
    SecurityFinding,
)
from securesense.domain.policies.evaluator import PolicyDecision
from securesense.domain.telemetry.models import NetworkEvent


@dataclass(frozen=True)
class DetectionResult:
    """Policy decision and optional security finding for a network event."""

    decision: PolicyDecision
    finding: SecurityFinding | None


class SecurityDetectionService:
    """Evaluate network events and create findings for denied activity."""

    def __init__(self, security_service: DeviceSecurityService) -> None:
        self._security_service = security_service

    def evaluate(self, event: NetworkEvent) -> DetectionResult:
        """Evaluate an event and produce a finding when it is denied."""
        decision = self._security_service.evaluate_event(event)

        if decision.allowed:
            return DetectionResult(decision=decision, finding=None)

        unknown_device = "is not registered" in decision.reason

        if unknown_device:
            rule_id = "NET-002"
            title = "Network activity from an unregistered device"
            description = (
                "A network event was received for a device that is not "
                "registered in SecureSense."
            )
        else:
            rule_id = "NET-001"
            title = "Unauthorized network communication"
            description = (
                "A registered device attempted communication that does "
                "not match its configured security policy."
            )

        finding = SecurityFinding(
            rule_id=rule_id,
            title=title,
            severity=FindingSeverity.HIGH,
            device_id=event.device_id,
            description=description,
            evidence={
                "device_id": event.device_id,
                "source_ip": event.source_ip,
                "destination": event.destination,
                "destination_ip": event.destination_ip,
                "protocol": event.protocol.value,
                "destination_port": event.destination_port,
                "network_zone": event.network_zone,
                "policy_reason": decision.reason,
            },
            recommendation=(
                "Verify the device identity and destination, review the "
                "communication policy, and investigate the event before "
                "taking response action."
            ),
            observed_at=event.timestamp,
        )

        return DetectionResult(decision=decision, finding=finding)
