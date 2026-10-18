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
    """Give each API test an isolated environment and database."""
    monkeypatch.setenv("SECURESENSE_ENV", "development")
    monkeypatch.delenv("SECURESENSE_API_TOKEN", raising=False)
    monkeypatch.setenv(
        "SECURESENSE_DATABASE_PATH",
        str(tmp_path / "securesense-test.sqlite3"),
    )


def test_dashboard_homepage_is_served() -> None:
    with TestClient(create_app(DEVICES_DIR)) as client:
        response = client.get("/")

    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "SecureSense | Security Operations" in response.text
    assert "/static/dashboard.css" in response.text
    assert "/static/dashboard.js" in response.text


@pytest.mark.parametrize(
    ("asset", "content_type"),
    [
        ("/static/dashboard.css", "text/css"),
        ("/static/dashboard.js", "javascript"),
    ],
)
def test_dashboard_static_assets_are_served(
    asset: str,
    content_type: str,
) -> None:
    with TestClient(create_app(DEVICES_DIR)) as client:
        response = client.get(asset)

    assert response.status_code == 200
    assert content_type in response.headers["content-type"]
    assert response.content


def test_api_data_routes_require_bearer_token_when_configured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SECURESENSE_API_TOKEN", "test-only-token")

    with TestClient(create_app(DEVICES_DIR)) as client:
        assert client.get("/health").status_code == 200
        assert client.get("/devices").status_code == 401
        assert client.get("/investigations").status_code == 401
        assert client.get("/investigations/INV-missing").status_code == 401

        headers = {"Authorization": "Bearer wrong-token"}
        assert client.get("/devices", headers=headers).status_code == 401

        headers = {"Authorization": "Bearer test-only-token"}
        assert client.get("/devices", headers=headers).status_code == 200
        assert client.get("/investigations", headers=headers).status_code == 200


@pytest.mark.parametrize(
    ("token", "should_start"),
    [
        ("", False),
        ("too-short", False),
        ("a" * 32, True),
    ],
)
def test_production_requires_strong_api_token(
    monkeypatch: pytest.MonkeyPatch,
    token: str,
    should_start: bool,
) -> None:
    monkeypatch.setenv("SECURESENSE_ENV", "production")
    monkeypatch.setenv("SECURESENSE_API_TOKEN", token)

    if not should_start:
        with pytest.raises(
            RuntimeError,
            match="Production requires SECURESENSE_API_TOKEN",
        ):
            create_app(DEVICES_DIR)
        return

    with TestClient(create_app(DEVICES_DIR)) as client:
        response = client.get("/devices")
        assert response.status_code == 401

        response = client.get(
            "/devices",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 200


def test_unknown_environment_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SECURESENSE_ENV", "staging")

    with pytest.raises(RuntimeError, match="SECURESENSE_ENV must be"):
        create_app(DEVICES_DIR)


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
    assert restored["result"] == {
        key: value for key, value in original.items()
        if key != "investigation_id"
    }
    assert any(
        item["investigation_id"] == investigation_id
        for item in listed_response.json()["investigations"]
    )


def test_get_unknown_investigation_returns_404() -> None:
    with TestClient(create_app(DEVICES_DIR)) as client:
        response = client.get("/investigations/INV-does-not-exist")

    assert response.status_code == 404


def test_telemetry_endpoints_return_persisted_readings() -> None:
    from datetime import UTC, datetime

    from securesense.domain.telemetry.sensor_reading import SensorReading

    with TestClient(create_app(DEVICES_DIR)) as client:
        repository = client.app.state.telemetry_repository
        repository.save(
            SensorReading(
                device_id="TEMP-001",
                metric="temperature",
                value=24.5,
                unit="celsius",
                timestamp=datetime(2026, 10, 17, tzinfo=UTC),
            )
        )

        latest = client.get("/telemetry/latest")
        history = client.get("/telemetry/readings")

    assert latest.status_code == 200
    assert latest.json()["count"] == 1
    assert latest.json()["readings"][0]["device_id"] == "TEMP-001"
    assert latest.json()["readings"][0]["value"] == 24.5

    assert history.status_code == 200
    assert history.json()["count"] == 1
    assert history.json()["readings"][0]["metric"] == "temperature"


def test_telemetry_endpoints_require_bearer_token_when_configured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SECURESENSE_API_TOKEN", "test-only-token")

    with TestClient(create_app(DEVICES_DIR)) as client:
        assert client.get("/telemetry/latest").status_code == 401
        assert client.get("/telemetry/readings").status_code == 401

        headers = {"Authorization": "Bearer test-only-token"}
        assert client.get("/telemetry/latest", headers=headers).status_code == 200
        assert client.get("/telemetry/readings", headers=headers).status_code == 200
