"""Validated models for safe, auditable incident response."""

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum


class ResponseAction(StrEnum):
    """Response actions SecureSense can recommend."""

    INVESTIGATE = "investigate"
    RECOMMEND_CONTAINMENT = "recommend_containment"
    ESCALATE = "escalate"


class ResponseExecutionMode(StrEnum):
    """Execution modes supported by the response workflow."""

    DRY_RUN = "dry_run"


@dataclass(frozen=True)
class ResponseRecord:
    """An immutable audit record of a proposed response action."""

    response_id: str
    incident_id: str
    device_id: str
    action: ResponseAction
    mode: ResponseExecutionMode
    reason: str
    actor: str
    created_at: datetime
    executed: bool = False

    def __post_init__(self) -> None:
        for field_name in (
            "response_id",
            "incident_id",
            "device_id",
            "reason",
            "actor",
        ):
            value = getattr(self, field_name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"'{field_name}' must not be empty")

        if not isinstance(self.action, ResponseAction):
            raise TypeError("'action' must be a valid ResponseAction")

        if not isinstance(self.mode, ResponseExecutionMode):
            raise TypeError("'mode' must be a valid ResponseExecutionMode")

        if not isinstance(self.created_at, datetime):
            raise TypeError("'created_at' must be a datetime")

        if (
            self.created_at.tzinfo is None
            or self.created_at.utcoffset() is None
        ):
            raise ValueError("'created_at' must be timezone-aware")

        if not isinstance(self.executed, bool):
            raise TypeError("'executed' must be a boolean")

        if self.mode is ResponseExecutionMode.DRY_RUN and self.executed:
            raise ValueError("Dry-run responses cannot be executed")
