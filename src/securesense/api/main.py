"""FastAPI application for SecureSense."""

import logging
import os
import threading
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Literal
from uuid import uuid4

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.encoders import jsonable_encoder
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field

from securesense.api.investigation_serializer import serialize_investigation_result
from securesense.application.service_factory import (
    SecureSenseServices,
    build_services,
)
from securesense.domain.policies.models import Protocol
from securesense.domain.telemetry.models import NetworkEvent
from securesense.infrastructure.mqtt.network_event_subscriber import (
    MqttNetworkEventSubscriber,
)
from securesense.infrastructure.mqtt.subscriber import MqttTelemetrySubscriber
from securesense.infrastructure.persistence.sqlite_investigation_repository import (
    SQLiteInvestigationRepository,
)
from securesense.infrastructure.persistence.sqlite_sensor_reading_repository import (
    SQLiteSensorReadingRepository,
)

PROJECT_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_DEVICES_DIR = PROJECT_ROOT / "devices"
DEFAULT_DATABASE_PATH = PROJECT_ROOT / ".data" / "securesense.sqlite3"
STATIC_DIR = Path(__file__).resolve().parent / "static"
logger = logging.getLogger(__name__)


class NetworkEventInput(BaseModel):
    """Validated network event submitted to the investigation API."""

    model_config = ConfigDict(extra="forbid")

    device_id: str = Field(min_length=1)
    source_ip: str = Field(min_length=1)
    destination: str = Field(min_length=1)
    destination_ip: str = Field(min_length=1)
    protocol: Literal["mqtt", "tcp", "udp"]
    destination_port: int = Field(ge=1, le=65535)
    network_zone: str = Field(min_length=1)
    timestamp: datetime


class InvestigationRequest(BaseModel):
    """Batch of network events to investigate."""

    model_config = ConfigDict(extra="forbid")

    events: list[NetworkEventInput] = Field(min_length=1, max_length=1000)


def create_app(devices_dir: Path | None = None) -> FastAPI:
    environment = os.environ.get("SECURESENSE_ENV", "development").strip().lower()
    configured_token = os.environ.get("SECURESENSE_API_TOKEN", "")

    if environment == "production":
        if len(configured_token) < 32:
            raise RuntimeError(
                "Production requires SECURESENSE_API_TOKEN with at least 32 characters."
            )
    elif environment not in {"development", "test"}:
        raise RuntimeError(
            "SECURESENSE_ENV must be development, test, or production."
        )
    """Create the API application with shared application services."""
    configured_dir = devices_dir or Path(
        os.environ.get("SECURESENSE_DEVICES_DIR", str(DEFAULT_DEVICES_DIR))
    )
    database_path = Path(
        os.environ.get("SECURESENSE_DATABASE_PATH", str(DEFAULT_DATABASE_PATH))
    )

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        """Build services once and retain them for the app's lifetime."""
        try:
            app.state.services = build_services(
                configured_dir,
                database_path=database_path,
            )
            app.state.investigation_repository = SQLiteInvestigationRepository(
                database_path
            )
            app.state.telemetry_repository = SQLiteSensorReadingRepository(
                database_path
            )
        except (OSError, ValueError, KeyError, TypeError) as exc:
            raise RuntimeError(
                "SecureSense device configuration could not be loaded."
            ) from exc

        mqtt_thread = None
        mqtt_stop = threading.Event()
        subscriber = None
        network_subscriber = None
        network_mqtt_thread = None

        if os.environ.get("SECURESENSE_MQTT_ENABLED", "").strip().lower() == "true":
            def save_sensor_reading(reading) -> None:
                try:
                    app.state.services.registry.get(reading.device_id)
                    app.state.telemetry_repository.save(reading)
                except KeyError:
                    logger.warning(
                        "Rejected telemetry from unregistered device %s",
                        reading.device_id,
                    )
                except (OSError, ValueError, TypeError):
                    logger.exception("Could not persist sensor telemetry")

            def report_mqtt_error(message: str) -> None:
                logger.warning("%s", message)

            mqtt_username = os.environ.get("SECURESENSE_MQTT_USERNAME")
            mqtt_password = os.environ.get("SECURESENSE_MQTT_PASSWORD")
            subscriber = MqttTelemetrySubscriber(
                on_reading=save_sensor_reading,
                on_error=report_mqtt_error,
                host=os.environ.get("SECURESENSE_MQTT_HOST", "127.0.0.1"),
                port=int(os.environ.get("SECURESENSE_MQTT_PORT", "1883")),
                username=mqtt_username,
                password=mqtt_password,
            )

            def run_mqtt_subscriber() -> None:
                while not mqtt_stop.is_set():
                    try:
                        subscriber.start()
                    except (OSError, ValueError) as exc:
                        logger.warning("MQTT connection unavailable: %s", exc)
                    if not mqtt_stop.is_set():
                        mqtt_stop.wait(5)

            mqtt_thread = threading.Thread(
                target=run_mqtt_subscriber,
                name="securesense-mqtt-telemetry",
                daemon=True,
            )
            mqtt_thread.start()

            def investigate_network_event(event: NetworkEvent) -> None:
                try:
                    result = app.state.services.investigator.investigate((event,))
                    if result.event_results and all(
                        item.duplicate_event for item in result.event_results
                    ):
                        logger.info(
                            "Ignored duplicate MQTT network event %s",
                            event.event_id,
                        )
                        return

                    investigation_id = f"INV-{uuid4().hex}"
                    app.state.investigation_repository.save(
                        investigation_id=investigation_id,
                        events=[jsonable_encoder(event)],
                        result=serialize_investigation_result(result),
                    )
                    logger.info("Persisted MQTT network investigation %s", investigation_id)
                except (OSError, ValueError, KeyError, TypeError):
                    logger.exception("Could not process MQTT network event")

            network_subscriber = MqttNetworkEventSubscriber(
                on_event=investigate_network_event,
                on_error=report_mqtt_error,
                host=os.environ.get("SECURESENSE_MQTT_HOST", "127.0.0.1"),
                port=int(os.environ.get("SECURESENSE_MQTT_PORT", "1883")),
                topic=os.environ.get("SECURESENSE_MQTT_NETWORK_TOPIC", "securesense/network-events"),
                username=mqtt_username,
                password=mqtt_password,
            )

            def run_network_subscriber() -> None:
                while not mqtt_stop.is_set():
                    try:
                        network_subscriber.start()
                    except (OSError, ValueError) as exc:
                        logger.warning("Network-event MQTT connection unavailable: %s", exc)
                    if not mqtt_stop.is_set():
                        mqtt_stop.wait(5)

            network_mqtt_thread = threading.Thread(
                target=run_network_subscriber,
                name="securesense-mqtt-network-events",
                daemon=True,
            )
            network_mqtt_thread.start()

        try:
            yield
        finally:
            mqtt_stop.set()
            if subscriber is not None:
                subscriber.stop()
            if network_subscriber is not None:
                network_subscriber.stop()
            if mqtt_thread is not None:
                mqtt_thread.join(timeout=3)
            if network_mqtt_thread is not None:
                network_mqtt_thread.join(timeout=3)
            del app.state.services

    app = FastAPI(
        title="SecureSense API",
        description=(
            "Industrial IoT security investigation API. "
            "Incidents, lifecycle audit history, and investigation records "
            "are stored in SQLite. Response recommendations remain dry-run."
        ),
        version="0.1.0",
        lifespan=lifespan,
    )

    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    @app.get("/", include_in_schema=False)
    def dashboard() -> FileResponse:
        """Serve the SecureSense browser dashboard."""
        return FileResponse(STATIC_DIR / "index.html")

    def require_api_token(
        authorization: str | None = Header(default=None),
    ) -> None:
        """Require a bearer token when API authentication is configured."""
        expected_token = os.environ.get("SECURESENSE_API_TOKEN")
        if not expected_token:
            return

        scheme, _, supplied_token = (authorization or "").partition(" ")
        if (
            scheme.lower() != "bearer"
            or not supplied_token
            or supplied_token != expected_token
        ):
            raise HTTPException(
                status_code=401,
                detail="A valid bearer token is required.",
                headers={"WWW-Authenticate": "Bearer"},
            )

    def get_services(request: Request) -> SecureSenseServices:
        """Retrieve the services initialized for this application."""
        services = getattr(request.app.state, "services", None)
        if services is None:
            raise HTTPException(
                status_code=503,
                detail="SecureSense services are not initialized.",
            )
        return services

    @app.get("/health", tags=["System"])
    def health() -> dict[str, str]:
        """Report that the API process is responsive."""
        return {"status": "ok", "service": "securesense-api"}

    @app.get("/devices", tags=["Devices"], dependencies=[Depends(require_api_token)])
    def list_devices(request: Request) -> dict[str, Any]:
        """List devices registered in the shared service registry."""
        services = get_services(request)
        devices = [
            {
                "device_id": registered.device.device_id,
                "device_type": registered.device.device_type.value,
                "purpose": registered.device.purpose,
                "network_zone": registered.device.network_zone.value,
            }
            for registered in services.registry.list_devices()
        ]
        return {"count": len(devices), "devices": devices}

    @app.get(
        "/telemetry/latest",
        tags=["IoT Telemetry"],
        dependencies=[Depends(require_api_token)],
    )
    def latest_telemetry(request: Request) -> dict[str, Any]:
        """Return the latest persisted reading for each device and metric."""
        repository = getattr(request.app.state, "telemetry_repository", None)
        if repository is None:
            raise HTTPException(
                status_code=503,
                detail="Telemetry storage is not initialized.",
            )
        readings = repository.latest_by_device()
        return {"count": len(readings), "readings": readings}

    @app.get(
        "/telemetry/readings",
        tags=["IoT Telemetry"],
        dependencies=[Depends(require_api_token)],
    )
    def list_telemetry(
        request: Request,
        limit: int = Query(default=100, ge=1, le=5000),
    ) -> dict[str, Any]:
        """Return recent persisted sensor readings, newest first."""
        repository = getattr(request.app.state, "telemetry_repository", None)
        if repository is None:
            raise HTTPException(
                status_code=503,
                detail="Telemetry storage is not initialized.",
            )
        readings = repository.list_recent(limit=limit)
        return {"count": len(readings), "readings": readings}

    @app.post("/investigations", tags=["Investigations"], dependencies=[Depends(require_api_token)])
    def investigate(
        payload: InvestigationRequest,
        request: Request,
    ) -> dict[str, Any]:
        """Investigate events using the shared security pipeline."""
        services = get_services(request)

        events = tuple(
            NetworkEvent(
                device_id=item.device_id.strip(),
                source_ip=item.source_ip.strip(),
                destination=item.destination.strip(),
                destination_ip=item.destination_ip.strip(),
                protocol=Protocol(item.protocol),
                destination_port=item.destination_port,
                network_zone=item.network_zone.strip(),
                timestamp=item.timestamp,
            )
            for item in payload.events
        )

        try:
            result = services.investigator.investigate(events)
        except (ValueError, KeyError, TypeError) as exc:
            raise HTTPException(
                status_code=422,
                detail="The supplied events could not be processed.",
            ) from exc

        event_results = []
        for event_result in result.event_results:
            finding = event_result.detection.finding
            assessment = event_result.risk_assessment
            incident = event_result.incident

            event_results.append(
                {
                    "allowed": event_result.detection.decision.allowed,
                    "decision_reason": event_result.detection.decision.reason,
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
                "incident_ids": [incident.incident_id for incident in linked.incidents],
            }
            for linked in result.correlated_paths
        ]

        response_body = {
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

        investigation_id = f"INV-{uuid4().hex}"
        repository = request.app.state.investigation_repository
        repository.save(
            investigation_id=investigation_id,
            events=[item.model_dump(mode="json") for item in payload.events],
            result=response_body,
        )
        response_body["investigation_id"] = investigation_id
        return response_body

    @app.get("/investigations", tags=["Investigations"], dependencies=[Depends(require_api_token)])
    def list_investigations(request: Request) -> dict[str, Any]:
        """List previously saved investigation records."""
        repository = getattr(
            request.app.state,
            "investigation_repository",
            None,
        )
        if repository is None:
            raise HTTPException(
                status_code=503,
                detail="Investigation storage is not initialized.",
            )

        records = repository.list_all()
        return {"count": len(records), "investigations": records}

    @app.get("/investigations/{investigation_id}", tags=["Investigations"], dependencies=[Depends(require_api_token)])
    def get_investigation(
        investigation_id: str,
        request: Request,
    ) -> dict[str, Any]:
        """Retrieve a saved investigation and its results."""
        repository = getattr(
            request.app.state,
            "investigation_repository",
            None,
        )
        if repository is None:
            raise HTTPException(
                status_code=503,
                detail="Investigation storage is not initialized.",
            )

        try:
            return repository.get(investigation_id)
        except KeyError as exc:
            raise HTTPException(
                status_code=404,
                detail=f"Investigation '{investigation_id}' was not found.",
            ) from exc

    return app


app = create_app()
