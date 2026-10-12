"""Immutable security finding models with preserved detection evidence."""

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from types import MappingProxyType


class FindingSeverity(StrEnum):
    """Severity assigned to a security finding."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class SecurityFinding:
    """A security finding linked to an observed event and its evidence."""

    rule_id: str
    title: str
    severity: FindingSeverity
    device_id: str
    description: str
    evidence: Mapping[str, object]
    recommendation: str
    observed_at: datetime

    def __post_init__(self) -> None:
        """Validate required fields and protect the evidence mapping."""
        for field_name in (
            "rule_id",
            "title",
            "device_id",
            "description",
            "recommendation",
        ):
            value = getattr(self, field_name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"'{field_name}' must be a non-empty string")

        if not isinstance(self.severity, FindingSeverity):
            raise TypeError("'severity' must be a FindingSeverity")

        if not isinstance(self.observed_at, datetime):
            raise TypeError("'observed_at' must be a datetime")

        if (
            self.observed_at.tzinfo is None
            or self.observed_at.utcoffset() is None
        ):
            raise ValueError("'observed_at' must include a timezone")

        if not isinstance(self.evidence, Mapping):
            raise TypeError("'evidence' must be a mapping")

        object.__setattr__(
            self,
            "evidence",
            MappingProxyType(dict(self.evidence)),
        )
