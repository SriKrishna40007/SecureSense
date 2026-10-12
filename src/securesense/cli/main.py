
"""SecureSense command-line interface."""

import logging
from pathlib import Path
from typing import Annotated

import typer
import yaml
from rich.console import Console

from securesense.application.device_registry import DeviceRegistry
from securesense.application.device_security_service import (
    DeviceSecurityService,
)
from securesense.application.incident_service import IncidentService
from securesense.application.reporting.investigation_report import (
    InvestigationReportFormatter,
)
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
from securesense.domain.response.models import ResponseAction
from securesense.domain.risk.scorer import RiskScorer
from securesense.infrastructure.config.device_loader import (
    DeviceConfigurationLoader,
)
from securesense.infrastructure.events.json_event_loader import (
    JsonEventLoader,
)
from securesense.infrastructure.mqtt.subscriber import (
    DEFAULT_TOPIC,
    MqttTelemetrySubscriber,
)

app = typer.Typer(
    name="securesense",
    help="Industrial IoT Cloud Security & Threat Detection Platform",
    no_args_is_help=True,
)
console = Console()


@app.callback()
def main() -> None:
    """SecureSense industrial IoT security tools."""


@app.command("listen")
def listen(
    host: Annotated[
        str,
        typer.Option(help="MQTT broker hostname or IP address."),
    ] = "127.0.0.1",
    port: Annotated[
        int,
        typer.Option(min=1, max=65535, help="MQTT broker port."),
    ] = 1883,
    topic: Annotated[
        str,
        typer.Option(help="MQTT topic filter."),
    ] = DEFAULT_TOPIC,
) -> None:
    """Listen for MQTT telemetry and display validated sensor readings."""
    logging.basicConfig(level=logging.WARNING)

    subscriber = MqttTelemetrySubscriber(
        host=host,
        port=port,
        topic=topic,
        on_reading=lambda reading: console.print(
            f"[green]TELEMETRY[/green] "
            f"{reading.device_id} | {reading.metric}="
            f"{reading.value:g} {reading.unit} | "
            f"{reading.timestamp.isoformat()}"
        ),
        on_error=lambda message: console.print(
            f"[red]MQTT ERROR[/red] {message}"
        ),
    )

    console.print(
        f"Connecting to MQTT broker {host}:{port}; topic: {topic}"
    )

    try:
        subscriber.start()
    except KeyboardInterrupt:
        console.print("\nStopping SecureSense telemetry listener...")
    except OSError as exc:
        raise typer.BadParameter(
            f"Could not connect to MQTT broker {host}:{port}: {exc}"
        ) from exc
    finally:
        subscriber.stop()


@app.command("report")
def report(
    events: Annotated[
        Path,
        typer.Option(help="Path to the JSON network-event file."),
    ] = Path("scenarios/events/investigation.json"),
    devices_dir: Annotated[
        Path,
        typer.Option(help="Directory containing device YAML configurations."),
    ] = Path("devices"),
    output: Annotated[
        Path | None,
        typer.Option(help="Optional path to save the text report."),
    ] = None,
    recommend_response: Annotated[
        bool,
        typer.Option(
            "--recommend-response",
            help=(
                "Record dry-run investigation recommendations "
                "for detected incidents."
            ),
        ),
    ] = False,
) -> None:
    """Investigate network events and generate a security report."""

    if not devices_dir.is_dir():
        raise typer.BadParameter(
            f"Device configuration directory not found: {devices_dir}",
            param_hint="--devices-dir",
        )

    config_files = sorted(
        (*devices_dir.glob("*.yaml"), *devices_dir.glob("*.yml"))
    )

    if not config_files:
        raise typer.BadParameter(
            f"No .yaml or .yml device configurations found in {devices_dir}",
            param_hint="--devices-dir",
        )

    try:
        registry = DeviceRegistry()
        device_loader = DeviceConfigurationLoader()

        for config_file in config_files:
            device, policy = device_loader.load(config_file)
            registry.register(device, policy)

        network_events = JsonEventLoader().load(events)

        security_service = DeviceSecurityService(
            registry=registry,
            policy_evaluator=PolicyEvaluator(),
        )
        detector = SecurityDetectionService(security_service)
        incident_service = IncidentService()

        pipeline = SecurityPipelineService(
            detector=detector,
            risk_scorer=RiskScorer(),
            incident_service=incident_service,
        )

        response_service = ResponseService(pipeline.incidents)

        investigator = SecurityInvestigationService(
            pipeline=pipeline,
            correlator=AttackPathCorrelator(),
            response_service=response_service,
        )

        result = investigator.investigate(network_events)

        if recommend_response:
            incident_ids = {
                event_result.incident.incident_id
                for event_result in result.event_results
                if event_result.incident is not None
            }

            for incident_id in sorted(incident_ids):
                investigator.recommend_response(
                    incident_id=incident_id,
                    action=ResponseAction.INVESTIGATE,
                    reason=(
                        "Review the incident evidence and validate the "
                        "suspected unauthorized network activity."
                    ),
                    actor="securesense-cli",
                )

        report_text = InvestigationReportFormatter().format(
            result,
            responses=response_service.list_records(),
        )

    except (
        OSError,
        ValueError,
        TypeError,
        KeyError,
        RuntimeError,
        yaml.YAMLError,
    ) as exc:
        raise typer.BadParameter(
            f"Investigation could not be completed: {exc}"
        ) from exc

    console.print(report_text, markup=False)

    if output is not None:
        try:
            output.write_text(report_text + "\n", encoding="utf-8")
        except OSError as exc:
            raise typer.BadParameter(
                f"Could not save report to '{output}': {exc}"
            ) from exc

        console.print(f"\nReport saved to: {output}")


if __name__ == "__main__":
    app()
