"""Evaluate network events against registered device security policies."""

from securesense.application.device_registry import DeviceRegistry
from securesense.domain.policies.evaluator import (
    PolicyDecision,
    PolicyEvaluator,
)
from securesense.domain.telemetry.models import NetworkEvent


class DeviceSecurityService:
    """Resolve device identity and evaluate its registered policy."""

    def __init__(
        self,
        registry: DeviceRegistry,
        policy_evaluator: PolicyEvaluator,
    ) -> None:
        self._registry = registry
        self._policy_evaluator = policy_evaluator

    def evaluate_event(self, event: NetworkEvent) -> PolicyDecision:
        """Deny unknown devices and evaluate registered device traffic."""
        try:
            registered = self._registry.get(event.device_id)
        except KeyError:
            return PolicyDecision(
                allowed=False,
                reason=(
                    f"Device '{event.device_id}' is not registered; "
                    "network event denied"
                ),
            )

        if event.device_id != registered.policy.device_id:
            return PolicyDecision(
                allowed=False,
                reason="Network event device does not match the policy device",
            )

        return self._policy_evaluator.evaluate(
            policy=registered.policy,
            protocol=event.protocol,
            destination=event.destination,
            port=event.destination_port,
            network_zone=event.network_zone,
        )
