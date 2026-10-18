"""Verify validated MQTT network events reach the security pipeline."""

import json
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest

from securesense.application.device_registry import DeviceRegistry
from securesense.application.device_security_service import DeviceSecurityService
from securesense.application.incident_service import IncidentService
from securesense.application.security_detection_service import (
    SecurityDetectionService,
)
from securesense.application.security_investigation_service import (
    SecurityInvestigationService,
)
from securesense.application.security_pipeline_service import (
    SecurityPipelineService,
)
from securesense.domain.attack_paths.correlator import AttackPathCorrelator
from securesense.domain.devices.models import Device, DeviceType, NetworkZone
from securesense.domain.policies.evaluator import PolicyEvaluator
from securesense.domain.policies.models import CommunicationPolicy, Protocol
from securesense.domain.risk.scorer import RiskScorer
from securesense.infrastructure.mqtt.network_event_subscriber import (
    MqttNetworkEventSubscriber,
)
from securesense.infrastructure.persistence.sqlite_incident_repository import (
    SQLiteIncidentRepository,
)


def build_investigator(
    database_path: str | None = None,
) -> SecurityInvestigationService:
    registry = DeviceRegistry()
    registry.register(
        device=Device(
            device_id="TEMP-001",
            device_type=DeviceType.TEMPERATURE_SENSOR,
            purpose="Monitor machine temperature",
            network_zone=NetworkZone.IOT,
        ),
        policy=CommunicationPolicy(
            device_id="TEMP-001",
            allowed_protocols=frozenset({Protocol.MQTT}),
            allowed_destinations=frozenset({"mqtt-gateway"}),
            allowed_ports=frozenset({8883}),
            allowed_network_zones=frozenset({NetworkZone.IOT.value}),
        ),
    )

    pipeline = SecurityPipelineService(
        detector=SecurityDetectionService(
            DeviceSecurityService(registry, PolicyEvaluator())
        ),
        risk_scorer=RiskScorer(),
        incident_service=IncidentService(
            SQLiteIncidentRepository(database_path)
            if database_path is not None
            else None
        ),
    )
    return SecurityInvestigationService(
        pipeline=pipeline,
        correlator=AttackPathCorrelator(),
    )


def network_event_payload(
    destination: str = "unauthorized-host",
    destination_port: int = 4444,
    event_id: str | None = None,
) -> bytes:
    payload = {
            "device_id": "TEMP-001",
            "source_ip": "192.0.2.10",
            "destination": destination,
            "destination_ip": "192.0.2.20",
            "protocol": "mqtt",
            "destination_port": destination_port,
            "network_zone": "iot",
            "timestamp": datetime(2026, 10, 10, 8, 0, tzinfo=UTC).isoformat(),
        }
    if event_id is not None:
        payload["event_id"] = event_id
    return json.dumps(payload).encode()


def deliver_mqtt_message(
    subscriber: MqttNetworkEventSubscriber,
    payload: bytes,
) -> None:
    message = SimpleNamespace(
        topic="securesense/network-events",
        payload=payload,
    )
    subscriber._on_message(subscriber.client, None, message)


def test_mqtt_policy_violation_reaches_investigation_and_creates_incident() -> None:
    investigator = build_investigator()
    errors: list[str] = []
    subscriber = MqttNetworkEventSubscriber(
        on_event=lambda event: investigator.investigate([event]),
        on_error=errors.append,
    )

    # Capture the investigation result as well as delivering the event.
    results = []
    subscriber.on_event = lambda event: results.append(
        investigator.investigate([event])
    )

    deliver_mqtt_message(subscriber, network_event_payload())

    assert errors == []
    assert len(results) == 1
    event_result = results[0].event_results[0]
    assert event_result.detection.finding is not None
    assert event_result.detection.finding.rule_id == "NET-001"
    assert event_result.risk_assessment is not None
    assert event_result.incident is not None
    assert event_result.incident.incident_id == "INC-0001"
    assert event_result.incident.device_id == "TEMP-001"
    assert investigator._pipeline.incidents.list_incidents() == [event_result.incident]


def test_mqtt_allowed_event_reaches_investigation_without_incident() -> None:
    investigator = build_investigator()
    results = []
    errors: list[str] = []
    subscriber = MqttNetworkEventSubscriber(
        on_event=lambda event: results.append(investigator.investigate([event])),
        on_error=errors.append,
    )

    deliver_mqtt_message(
        subscriber,
        network_event_payload(
            destination="mqtt-gateway",
            destination_port=8883,
        ),
    )

    assert errors == []
    assert len(results) == 1
    event_result = results[0].event_results[0]
    assert event_result.detection.decision.allowed is True
    assert event_result.detection.finding is None
    assert event_result.incident is None
    assert investigator._pipeline.incidents.list_incidents() == []


def test_malformed_mqtt_event_is_rejected_without_investigation() -> None:
    investigator = build_investigator()
    results = []
    errors: list[str] = []
    subscriber = MqttNetworkEventSubscriber(
        on_event=lambda event: results.append(investigator.investigate([event])),
        on_error=errors.append,
    )

    deliver_mqtt_message(subscriber, b'{"device_id":')

    assert results == []
    assert len(errors) == 1
    assert "Rejected network event" in errors[0]
    assert investigator._pipeline.incidents.list_incidents() == []



def test_duplicate_mqtt_event_does_not_create_another_incident(
    tmp_path,
) -> None:
    database_path = str(tmp_path / "securesense.sqlite3")
    payload = network_event_payload(event_id="mqtt-event-001")

    first_investigator = build_investigator(database_path)
    first_results = []
    first_subscriber = MqttNetworkEventSubscriber(
        on_event=lambda event: first_results.append(
            first_investigator.investigate([event])
        ),
        on_error=lambda error: pytest.fail(error),
    )
    deliver_mqtt_message(first_subscriber, payload)

    first_event_result = first_results[0].event_results[0]
    assert first_event_result.incident is not None
    assert first_event_result.duplicate_event is False
    assert len(first_investigator._pipeline.incidents.list_incidents()) == 1

    # Simulate a process restart by constructing a new investigator and
    # repository against the same database.
    restarted_investigator = build_investigator(database_path)
    repeated_results = []
    repeated_subscriber = MqttNetworkEventSubscriber(
        on_event=lambda event: repeated_results.append(
            restarted_investigator.investigate([event])
        ),
        on_error=lambda error: pytest.fail(error),
    )
    deliver_mqtt_message(repeated_subscriber, payload)

    repeated_result = repeated_results[0].event_results[0]
    assert repeated_result.duplicate_event is True
    assert repeated_result.incident is None
    assert len(restarted_investigator._pipeline.incidents.list_incidents()) == 1


def test_duplicate_allowed_mqtt_event_is_also_deduplicated(tmp_path) -> None:
    database_path = str(tmp_path / "securesense.sqlite3")
    payload = network_event_payload(
        destination="mqtt-gateway",
        destination_port=8883,
        event_id="mqtt-allowed-001",
    )
    investigator = build_investigator(database_path)
    results = []
    subscriber = MqttNetworkEventSubscriber(
        on_event=lambda event: results.append(investigator.investigate([event])),
        on_error=lambda error: pytest.fail(error),
    )

    deliver_mqtt_message(subscriber, payload)
    deliver_mqtt_message(subscriber, payload)

    assert len(results) == 2
    assert results[0].event_results[0].duplicate_event is False
    assert results[1].event_results[0].duplicate_event is True
    assert investigator._pipeline.incidents.list_incidents() == []
