from securesense.domain.policies.evaluator import PolicyEvaluator
from securesense.domain.policies.models import CommunicationPolicy, Protocol


def make_policy() -> CommunicationPolicy:
    return CommunicationPolicy(
        device_id="TEMP-001",
        allowed_protocols=frozenset({Protocol.MQTT}),
        allowed_destinations=frozenset({"mqtt-gateway"}),
        allowed_ports=frozenset({8883}),
        allowed_network_zones=frozenset({"iot"}),
    )


def test_allows_expected_communication() -> None:
    policy = make_policy()

    decision = PolicyEvaluator().evaluate(
        policy=policy,
        protocol=Protocol.MQTT,
        destination="mqtt-gateway",
        port=8883,
        network_zone="iot",
    )

    assert decision.allowed is True
    assert decision.reason == "Communication matches the device security policy"


def test_denies_unexpected_protocol() -> None:
    policy = make_policy()

    decision = PolicyEvaluator().evaluate(
        policy=policy,
        protocol=Protocol.TCP,
        destination="mqtt-gateway",
        port=8883,
        network_zone="iot",
    )

    assert decision.allowed is False
    assert "Protocol" in decision.reason


def test_denies_unexpected_destination() -> None:
    policy = make_policy()

    decision = PolicyEvaluator().evaluate(
        policy=policy,
        protocol=Protocol.MQTT,
        destination="unknown-server",
        port=8883,
        network_zone="iot",
    )

    assert decision.allowed is False
    assert "Destination" in decision.reason


def test_denies_unexpected_port() -> None:
    policy = make_policy()

    decision = PolicyEvaluator().evaluate(
        policy=policy,
        protocol=Protocol.MQTT,
        destination="mqtt-gateway",
        port=4444,
        network_zone="iot",
    )

    assert decision.allowed is False
    assert "Port" in decision.reason


def test_denies_unexpected_network_zone() -> None:
    policy = make_policy()

    decision = PolicyEvaluator().evaluate(
        policy=policy,
        protocol=Protocol.MQTT,
        destination="mqtt-gateway",
        port=8883,
        network_zone="application",
    )

    assert decision.allowed is False
    assert "Network zone" in decision.reason
