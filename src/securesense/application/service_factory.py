"""Construct the application services used by SecureSense interfaces."""

from dataclasses import dataclass
from pathlib import Path

from securesense.application.device_registry import DeviceRegistry
from securesense.application.device_security_service import (
    DeviceSecurityService,
)
from securesense.application.incident_service import IncidentService
from securesense.application.response_service import ResponseService
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
from securesense.domain.policies.evaluator import PolicyEvaluator
from securesense.domain.risk.scorer import RiskScorer
from securesense.infrastructure.config.device_loader import (
    DeviceConfigurationLoader,
)
from securesense.infrastructure.persistence.sqlite_incident_repository import (
    SQLiteIncidentRepository,
)


@dataclass(frozen=True)
class SecureSenseServices:
    """Services assembled for one SecureSense interface or request."""

    registry: DeviceRegistry
    investigator: SecurityInvestigationService


def build_services(
    devices_dir: Path,
    database_path: Path | str | None = None,
) -> SecureSenseServices:
    """Load device policies and construct the security service pipeline."""
    if not devices_dir.is_dir():
        raise ValueError(f"Device configuration directory not found: {devices_dir}")

    config_files = sorted((*devices_dir.glob("*.yaml"), *devices_dir.glob("*.yml")))
    if not config_files:
        raise ValueError(
            f"No .yaml or .yml device configurations found in {devices_dir}"
        )

    registry = DeviceRegistry()
    loader = DeviceConfigurationLoader()

    for config_file in config_files:
        device, policy = loader.load(config_file)
        registry.register(device, policy)

    security_service = DeviceSecurityService(
        registry=registry,
        policy_evaluator=PolicyEvaluator(),
    )
    detector = SecurityDetectionService(security_service)
    incident_repository = (
        SQLiteIncidentRepository(database_path) if database_path is not None else None
    )
    incident_service = IncidentService(incident_repository)

    pipeline = SecurityPipelineService(
        detector=detector,
        risk_scorer=RiskScorer(),
        incident_service=incident_service,
    )
    investigator = SecurityInvestigationService(
        pipeline=pipeline,
        correlator=AttackPathCorrelator(),
        response_service=ResponseService(pipeline.incidents),
    )

    return SecureSenseServices(
        registry=registry,
        investigator=investigator,
    )
