"""Application service for safe, auditable dry-run responses."""

from datetime import UTC, datetime

from securesense.application.incident_service import IncidentService
from securesense.domain.incidents.models import Incident
from securesense.domain.response.models import (
    ResponseAction,
    ResponseExecutionMode,
    ResponseRecord,
)


class ResponseService:
    """Create and retrieve response recommendations without executing them."""

    def __init__(self, incident_service: IncidentService) -> None:
        self._incident_service = incident_service
        self._records: dict[str, ResponseRecord] = {}
        self._next_id = 1

    def recommend(
        self,
        incident_id: str,
        action: ResponseAction,
        reason: str,
        actor: str,
    ) -> ResponseRecord:
        """Record a proposed response without changing incident or device state."""
        if not isinstance(incident_id, str) or not incident_id.strip():
            raise ValueError("'incident_id' must be a non-empty string")

        if not isinstance(action, ResponseAction):
            raise TypeError("'action' must be a ResponseAction")

        if not isinstance(reason, str) or not reason.strip():
            raise ValueError("'reason' must be a non-empty string")

        if not isinstance(actor, str) or not actor.strip():
            raise ValueError("'actor' must be a non-empty string")

        incident: Incident = self._incident_service.get(incident_id)

        response_id = f"RESP-{self._next_id:04d}"
        record = ResponseRecord(
            response_id=response_id,
            incident_id=incident.incident_id,
            device_id=incident.device_id,
            action=action,
            mode=ResponseExecutionMode.DRY_RUN,
            reason=reason.strip(),
            actor=actor.strip(),
            created_at=datetime.now(UTC),
            executed=False,
        )

        self._records[response_id] = record
        self._next_id += 1
        return record

    def get(self, response_id: str) -> ResponseRecord:
        """Retrieve a response audit record by ID."""
        try:
            return self._records[response_id]
        except KeyError:
            raise KeyError(
                f"Response '{response_id}' was not found"
            ) from None

    def list_records(self) -> list[ResponseRecord]:
        """Return response records in creation order."""
        return list(self._records.values())
