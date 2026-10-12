from dataclasses import dataclass

from securesense.domain.policies.models import CommunicationPolicy, Protocol


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    reason: str


class PolicyEvaluator:
    def evaluate(
        self,
        policy: CommunicationPolicy,
        protocol: Protocol,
        destination: str,
        port: int,
        network_zone: str,
    ) -> PolicyDecision:
        if protocol not in policy.allowed_protocols:
            return PolicyDecision(
                allowed=False,
                reason=f"Protocol '{protocol}' is not allowed",
            )

        if destination not in policy.allowed_destinations:
            return PolicyDecision(
                allowed=False,
                reason=f"Destination '{destination}' is not allowed",
            )

        if port not in policy.allowed_ports:
            return PolicyDecision(
                allowed=False,
                reason=f"Port '{port}' is not allowed",
            )

        if network_zone not in policy.allowed_network_zones:
            return PolicyDecision(
                allowed=False,
                reason=f"Network zone '{network_zone}' is not allowed",
            )

        return PolicyDecision(
            allowed=True,
            reason="Communication matches the device security policy",
        )
