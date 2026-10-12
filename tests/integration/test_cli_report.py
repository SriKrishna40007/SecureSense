"""Integration tests for the SecureSense report CLI command."""

import json
from pathlib import Path

from typer.testing import CliRunner

from securesense.cli.main import app

runner = CliRunner()


def create_device_config(devices_dir: Path) -> None:
    """Create a minimal valid device configuration for CLI tests."""
    (devices_dir / "temp-001.yaml").write_text(
        """
device_id: TEMP-001
device_type: temperature_sensor
purpose: Test temperature sensor
network_zone: iot

security_policy:
  allowed_protocols:
    - mqtt
  allowed_destinations:
    - mqtt-gateway
  allowed_ports:
    - 8883
  allowed_network_zones:
    - iot
""".lstrip(),
        encoding="utf-8",
    )


def create_events_file(events_file: Path) -> None:
    """Create a valid network-event input file."""
    events_file.write_text(
        json.dumps(
            {
                "events": [
                    {
                        "device_id": "TEMP-001",
                        "source_ip": "192.0.2.10",
                        "destination": "unapproved-host",
                        "destination_ip": "192.0.2.30",
                        "protocol": "mqtt",
                        "destination_port": 4444,
                        "network_zone": "iot",
                        "timestamp": "2026-10-10T08:00:00+00:00",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )


def test_report_command_generates_report_and_saves_file(
    tmp_path: Path,
) -> None:
    """A valid investigation produces console output and a report file."""
    devices_dir = tmp_path / "devices"
    devices_dir.mkdir()
    create_device_config(devices_dir)

    events_file = tmp_path / "events.json"
    create_events_file(events_file)

    output_file = tmp_path / "reports" / "investigation.txt"
    output_file.parent.mkdir()

    result = runner.invoke(
        app,
        [
            "report",
            "--events",
            str(events_file),
            "--devices-dir",
            str(devices_dir),
            "--output",
            str(output_file),
        ],
    )

    assert result.exit_code == 0, result.output
    assert "SECURESENSE INVESTIGATION REPORT" in result.output
    assert "Report saved to:" in result.output
    assert output_file.is_file()

    saved_report = output_file.read_text(encoding="utf-8")
    assert "SECURESENSE INVESTIGATION REPORT" in saved_report
    assert "TEMP-001" in saved_report


def test_report_command_rejects_missing_devices_directory(
    tmp_path: Path,
) -> None:
    """A missing device directory produces a CLI error."""
    events_file = tmp_path / "events.json"
    create_events_file(events_file)

    result = runner.invoke(
        app,
        [
            "report",
            "--events",
            str(events_file),
            "--devices-dir",
            str(tmp_path / "missing-devices"),
        ],
    )

    assert result.exit_code != 0
    assert "Device configuration directory not found" in result.output


def test_report_command_rejects_invalid_json(
    tmp_path: Path,
) -> None:
    """Malformed event JSON is reported as a CLI error."""
    devices_dir = tmp_path / "devices"
    devices_dir.mkdir()
    create_device_config(devices_dir)

    events_file = tmp_path / "invalid-events.json"
    events_file.write_text("{invalid json", encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "report",
            "--events",
            str(events_file),
            "--devices-dir",
            str(devices_dir),
        ],
    )

    assert result.exit_code != 0
    assert "Investigation could not be completed" in result.output

def test_report_command_records_dry_run_recommendations(
    tmp_path: Path,
) -> None:
    """The opt-in flag records recommendations without executing them."""
    devices_dir = tmp_path / "devices"
    devices_dir.mkdir()
    create_device_config(devices_dir)

    events_file = tmp_path / "events.json"
    create_events_file(events_file)

    result = runner.invoke(
        app,
        [
            "report",
            "--events",
            str(events_file),
            "--devices-dir",
            str(devices_dir),
            "--recommend-response",
        ],
    )

    assert result.exit_code == 0, result.output
    assert "DRY RUN" in result.output
    assert "NOT EXECUTED" in result.output
    assert "RESP-0001" in result.output
    assert "investigate" in result.output
    assert "securesense-cli" in result.output
