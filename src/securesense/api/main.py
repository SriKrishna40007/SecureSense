"""FastAPI application for SecureSense."""

import os
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Literal
from uuid import uuid4

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field

from securesense.application.service_factory import (
    SecureSenseServices,
    build_services,
)
from securesense.domain.policies.models import Protocol
from securesense.domain.telemetry.models import NetworkEvent
from securesense.infrastructure.persistence.sqlite_investigation_repository import (
    SQLiteInvestigationRepository,
)

PROJECT_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_DEVICES_DIR = PROJECT_ROOT / "devices"
DEFAULT_DATABASE_PATH = PROJECT_ROOT / ".data" / "securesense.sqlite3"


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
        except (OSError, ValueError, KeyError, TypeError) as exc:
            raise RuntimeError(
                "SecureSense device configuration could not be loaded."
            ) from exc

        yield

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

    @app.get("/devices", tags=["Devices"])
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

    @app.post("/investigations", tags=["Investigations"])
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

    @app.get("/investigations", tags=["Investigations"])
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

    @app.get("/investigations/{investigation_id}", tags=["Investigations"])
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
