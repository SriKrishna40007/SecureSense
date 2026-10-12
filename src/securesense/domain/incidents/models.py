"""Incident lifecycle models with validated transitions and audit history."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import ClassVar


class IncidentStatus(StrEnum):
    """Supported incident lifecycle states."""

    OPEN = "open"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    RESOLVED = "resolved"
    CLOSED = "closed"


@dataclass(frozen=True)
class IncidentAuditEntry:
    """Record a single incident state transition."""

    previous_status: IncidentStatus
    new_status: IncidentStatus
    actor: str
    note: str
    occurred_at: datetime


@dataclass
class Incident:
    """Track an incident and preserve its transition history."""

    incident_id: str
    title: str
    device_id: str
    risk_score: int
    created_at: datetime
    updated_at: datetime
    status: IncidentStatus = IncidentStatus.OPEN
    history: list[IncidentAuditEntry] = field(default_factory=list)

    _ALLOWED_TRANSITIONS: ClassVar[dict[IncidentStatus, set[IncidentStatus]]] = {
        IncidentStatus.OPEN: {IncidentStatus.INVESTIGATING},
        IncidentStatus.INVESTIGATING: {
            IncidentStatus.CONTAINED,
            IncidentStatus.RESOLVED,
        },
        IncidentStatus.CONTAINED: {IncidentStatus.INVESTIGATING,
                                   IncidentStatus.RESOLVED},
        IncidentStatus.RESOLVED: {IncidentStatus.CLOSED},
        IncidentStatus.CLOSED: set(),
    }

    def __post_init__(self) -> None:
        """Validate required fields and initial timestamps."""
        for name in ("incident_id", "title", "device_id"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"'{name}' must be a non-empty string")

        if isinstance(self.risk_score, bool) or not isinstance(
            self.risk_score, int
        ):
            raise TypeError("'risk_score' must be an integer")

        if not 0 <= self.risk_score <= 100:
            raise ValueError("'risk_score' must be between 0 and 100")

        for name in ("created_at", "updated_at"):
            value = getattr(self, name)
            if (
                not isinstance(value, datetime)
                or value.tzinfo is None
                or value.utcoffset() is None
            ):
                raise ValueError(f"'{name}' must be timezone-aware")

        if self.updated_at < self.created_at:
            raise ValueError("'updated_at' must not precede 'created_at'")

        if not isinstance(self.status, IncidentStatus):
            raise TypeError("'status' must be an IncidentStatus")

        if not isinstance(self.history, list):
            raise TypeError("'history' must be a list")

    def transition_to(
        self,
        new_status: IncidentStatus,
        actor: str,
        note: str,
        at: datetime,
    ) -> None:
        """Apply a permitted transition and append an audit entry."""
        if not isinstance(new_status, IncidentStatus):
            raise TypeError("'new_status' must be an IncidentStatus")

        if not isinstance(actor, str) or not actor.strip():
            raise ValueError("'actor' must be a non-empty string")

        if not isinstance(note, str) or not note.strip():
            raise ValueError("'note' must be a non-empty string")

        if (
            not isinstance(at, datetime)
            or at.tzinfo is None
            or at.utcoffset() is None
        ):
            raise ValueError("'at' must be timezone-aware")

        if at < self.updated_at:
            raise ValueError("Transition timestamp must not precede last update")

        allowed = self._ALLOWED_TRANSITIONS[self.status]
        if new_status not in allowed:
            raise ValueError(
                f"Invalid incident transition: "
                f"{self.status.value} -> {new_status.value}"
            )

        entry = IncidentAuditEntry(
            previous_status=self.status,
            new_status=new_status,
            actor=actor.strip(),
            note=note.strip(),
            occurred_at=at,
        )

        self.history.append(entry)
        self.status = new_status
        self.updated_at = at
