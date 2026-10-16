"""Integration tests for the SecureSense REST API."""

from datetime import datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from securesense.api.main import create_app

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEVICES_DIR = PROJECT_ROOT / "devices"


@pytest.fixture(autouse=True)
def isolate_test_database(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Give each API test an independent persistent database."""
    monkeypatch.setenv(
        "SECURESENSE_DATABASE_PATH",
        str(tmp_path / "securesense-test.sqlite3"),
    )


def test_health_endpoint() -> None:
    with TestClient(create_app(DEVICES_DIR)) as client:
        response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "service": "securesense-api",
    }


def test_devices_endpoint_lists_configured_devices() -> None:
    with TestClient(create_app(DEVICES_DIR)) as client:
        response = client.get("/devices")

    assert response.status_code == 200
    body = response.json()

    assert body["count"] == 3
    assert {device["device_id"] for device in body["devices"]} == {
        "TEMP-001",
        "PRESS-001",
        "VIB-001",
    }


def test_devices_endpoint_reports_missing_configuration(
    tmp_path: Path,
) -> None:
    with (
        pytest.raises(
            RuntimeError,
            match="SecureSense device configuration could not be loaded",
        ),
        TestClient(create_app(tmp_path / "missing")),
    ):
        pass


def test_investigation_endpoint_returns_security_results() -> None:
    payload = {
        "events": [
            {
                "device_id": "TEMP-001",
                "source_ip": "192.0.2.10",
                "destination": "unapproved-host",
                "destination_ip": "192.0.2.30",
                "protocol": "tcp",
                "destination_port": 443,
                "network_zone": "iot",
                "timestamp": "2026-10-11T10:00:00+00:00",
            },
            {
                "device_id": "UNKNOWN-001",
                "source_ip": "192.0.2.30",
                "destination": "unknown-service",
                "destination_ip": "192.0.2.40",
                "protocol": "tcp",
                "destination_port": 443,
                "network_zone": "iot",
                "timestamp": "2026-10-11T10:05:00+00:00",
            },
        ]
    }

    with TestClient(create_app(DEVICES_DIR)) as client:
        response = client.post("/investigations", json=payload)

    assert response.status_code == 200
    body = response.json()
    assert body["events_investigated"] == 2
    assert body["findings_count"] == 2
    assert body["incidents_count"] == 2
    assert len(body["event_results"]) == 2

    first_result = body["event_results"][0]
    assert first_result["finding"]["rule_id"] == "NET-001"
    assert first_result["risk_assessment"]["score"] == 70
    assert first_result["incident"]["status"] == "open"

    second_result = body["event_results"][1]
    assert second_result["finding"]["rule_id"] == "NET-002"
    assert second_result["risk_assessment"]["score"] == 70
    assert second_result["incident"]["status"] == "open"

    assert body["candidate_attack_paths_count"] >= 1
    assert all(
        "requires analyst validation" in path["classification"]
        for path in body["candidate_attack_paths"]
    )
    assert body["response_execution"] == ("No response actions were executed.")


def test_investigation_endpoint_rejects_invalid_request() -> None:
    with TestClient(create_app(DEVICES_DIR)) as client:
        response = client.post(
            "/investigations",
            json={
                "events": [
                    {
                        "device_id": "TEMP-001",
                        "protocol": "invalid-protocol",
                    }
                ]
            },
        )

    assert response.status_code == 422


def test_investigation_endpoint_rejects_empty_event_batch() -> None:
    with TestClient(create_app(DEVICES_DIR)) as client:
        response = client.post("/investigations", json={"events": []})

    assert response.status_code == 422


def test_incident_numbering_persists_across_requests() -> None:
    payload = {
        "events": [
            {
                "device_id": "UNKNOWN-001",
                "source_ip": "192.0.2.50",
                "destination": "unknown-service",
                "destination_ip": "192.0.2.60",
                "protocol": "tcp",
                "destination_port": 443,
                "network_zone": "iot",
                "timestamp": "2026-10-11T11:00:00+00:00",
            }
        ]
    }

    with TestClient(create_app(DEVICES_DIR)) as client:
        first = client.post("/investigations", json=payload)
        second = client.post("/investigations", json=payload)

    assert first.status_code == 200
    assert second.status_code == 200
    assert first.json()["event_results"][0]["incident"]["incident_id"] == "INC-0001"
    assert second.json()["event_results"][0]["incident"]["incident_id"] == "INC-0002"


def test_investigation_survives_api_restart() -> None:
    """Saved investigation results remain available after app restart."""
    payload = {
        "events": [
            {
                "device_id": "UNKNOWN-001",
                "source_ip": "192.0.2.50",
                "destination": "unknown-service",
                "destination_ip": "192.0.2.60",
                "protocol": "tcp",
                "destination_port": 443,
                "network_zone": "iot",
                "timestamp": "2026-10-11T11:00:00+00:00",
            }
        ]
    }

    with TestClient(create_app(DEVICES_DIR)) as first_client:
        submitted = first_client.post("/investigations", json=payload)

        assert submitted.status_code == 200
        original = submitted.json()
        investigation_id = original["investigation_id"]

    with TestClient(create_app(DEVICES_DIR)) as second_client:
        restored_response = second_client.get(f"/investigations/{investigation_id}")
        listed_response = second_client.get("/investigations")

    assert restored_response.status_code == 200
    restored = restored_response.json()

    assert restored["investigation_id"] == investigation_id
    restored_event = restored["events"][0]
    submitted_event = payload["events"][0]

    assert {
        key: value for key, value in restored_event.items() if key != "timestamp"
    } == {key: value for key, value in submitted_event.items() if key != "timestamp"}
    assert datetime.fromisoformat(
        restored_event["timestamp"]
    ) == datetime.fromisoformat(submitted_event["timestamp"])
    assert restored["result"]["findings_count"] == original["findings_count"]
    assert restored["result"]["incidents_count"] == original["incidents_count"]
    assert restored["result"]["event_results"] == original["event_results"]
    assert any(
        item["investigation_id"] == investigation_id
        for item in listed_response.json()["investigations"]
    )


def test_get_unknown_investigation_returns_404() -> None:
    with TestClient(create_app(DEVICES_DIR)) as client:
        response = client.get("/investigations/INV-does-not-exist")

    assert response.status_code == 404
