# SecureSense
[![Release](https://img.shields.io/github/v/release/SriKrishna40007/SecureSense)](https://github.com/SriKrishna40007/SecureSense/releases)
[![SecureSense CI](https://github.com/SriKrishna40007/SecureSense/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/SriKrishna40007/SecureSense/actions)

## Industrial IoT Cloud Security & Threat Detection Platform

SecureSense is a Python-based security investigation platform for industrial
IoT environments. It combines device communication policies, telemetry
validation, network-event analysis, risk scoring, incident management, and
evidence-based investigation reports.

The project demonstrates how an industrial IoT security workflow can identify
unauthorized communication and activity from unregistered devices using
simulated network events and configurable device policies.

> **Project status:** Portfolio engineering project. The investigation
> pipeline, simulated report workflow, automated tests, and Docker image have
> been implemented and locally validated. This is not a production-certified
> security monitoring or automated enforcement system.

## Key capabilities

- **IoT device inventory:** Register devices and load their communication
  policies from YAML configuration files.
- **Communication policy evaluation:** Check observed network events against
  configured protocols, destinations, ports, and network zones.
- **Telemetry ingestion:** Validate sensor payloads and support MQTT-based
  telemetry, including a virtual ESP32/DHT22 sensor workflow.
- **Security detection:** Generate evidence-backed findings for unauthorized
  communication and unregistered devices.
- **Risk assessment:** Assign configurable severity-based risk scores.
- **Incident management:** Create incidents and track their lifecycle with
  auditable state transitions.
- **Attack-path correlation:** Identify candidate relationships between
  findings using shared network evidence. Correlation is not proof of an attack.
- **Response audit:** Record recommendations in dry-run mode without executing
  network changes or device isolation.
- **Investigation reporting:** Produce readable reports containing findings,
  evidence, risk assessments, incidents, candidate attack paths, and limitations.
- **Containerization and CI:** Build a Docker image and run automated tests
  and lint checks through GitHub Actions.

## Architecture

```text
Virtual ESP32 + DHT22 sensor
             |
             v
       Serial telemetry
             |
             v
       Serial bridge
             |
             v
     MQTT broker (local)
             |
             v
    MQTT telemetry listener

Simulated network-event JSON + device YAML policies
                         |
                         v
                Event validation
                         |
                         v
              Security policy evaluation
                         |
                         v
                 Security findings
                         |
                         v
                Risk assessments
                         |
                         v
                Incident creation
                         |
                         v
             Investigation and correlation
                         |
                         v
               Auditable text report
```

The sensor workflow and investigation-report workflow are related project
capabilities, but the report command currently investigates supplied JSON
network events. It does not automatically derive those network events from
live MQTT telemetry.

## Technology stack

- Python 3.13+
- Typer CLI and Rich terminal output
- Paho MQTT
- PyYAML
- pytest and Ruff
- uv dependency management
- Docker and Docker Compose
- GitHub Actions
- PlatformIO, ESP32, DHT22, and Wokwi for virtual IoT simulation

## Project layout

```text
SecureSense/
├── .github/workflows/ci.yml
├── devices/                 # Device and communication policies
├── infrastructure/
│   └── mosquitto/config/    # Local MQTT broker configuration
├── scenarios/
│   └── events/              # Simulated network-event inputs
├── src/securesense/
│   ├── application/         # Investigation and reporting workflows
│   ├── cli/                 # Command-line interface
│   ├── domain/              # Security and business models
│   └── infrastructure/      # Configuration, events, and MQTT adapters
├── tests/
│   ├── integration/
│   └── unit/
├── wokwi/temp-001/          # Virtual ESP32 sensor project
├── compose.yaml
├── Dockerfile
├── pyproject.toml
└── uv.lock
```

## Getting started

### Requirements

- Python 3.13 or later
- uv
- Git
- Docker Desktop, if running the container or local MQTT broker

### Install dependencies

From the repository root:

```bash
uv sync --locked --all-groups
```

### Inspect CLI commands

```bash
uv run securesense --help
uv run securesense report --help
uv run securesense listen --help
```

### Run the sample investigation

```bash
uv run securesense report \
  --events scenarios/events/investigation.json \
  --devices-dir devices \
  --output reports/investigation-report.txt
```

The command loads the configured devices and simulated events, evaluates
security policies, creates findings and incidents, correlates candidate
attack paths, and writes a text report.

The output directory must already exist. To create it if needed:

```bash
mkdir -p reports
```

## REST API

Start the API from the repository root:

```bash
uv run uvicorn securesense.api.main:app --host 127.0.0.1 --port 8000
```

The server binds to localhost. Open http://127.0.0.1:8000/docs for interactive API documentation.

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/health` | Check API responsiveness |
| GET | `/devices` | List configured IoT devices |
| POST | `/investigations` | Investigate supplied network events |

Check the health endpoint with `curl -i http://127.0.0.1:8000/health`. List devices with `curl http://127.0.0.1:8000/devices`.

Create a sample API request file in the repository root:

```bash
cat > investigation-request.json <<'JSON'
{
  "events": [
    {
      "device_id": "TEMP-001",
      "source_ip": "192.0.2.10",
      "destination": "mqtt-gateway",
      "destination_ip": "192.0.2.20",
      "protocol": "mqtt",
      "destination_port": 8883,
      "network_zone": "iot",
      "timestamp": "2026-10-10T08:00:00+00:00"
    }
  ]
}
JSON
```

With the API running, submit the request:

```bash
curl -sS -X POST http://127.0.0.1:8000/investigations \
  -H "Content-Type: application/json" \
  --data-binary @investigation-request.json
```

The response contains the investigation results as JSON. The example uses
documentation-range IP addresses and does not contact real devices. Remove
the temporary request file when finished with `rm investigation-request.json`.

The API processes submitted network events; it does not automatically convert MQTT telemetry into network-security events. Incident state is held in memory and is not persisted across restarts. No response actions are executed. Stop the server with `Ctrl+C`.


### Run tests and lint checks

```bash
uv run pytest -v
uv run ruff check src tests
uv lock --check
```

## Run with Docker

Build the image:

```bash
docker build -t securesense:local .
```

Run the bundled sample investigation:

```bash
docker run --rm securesense:local
```

The image installs SecureSense, includes the device configurations and sample
scenario, and runs as a non-root user.

To investigate a different event file, mount the file into the container and
override the report arguments. For example, if `custom-events.json` is in the
current directory:

```bash
docker run --rm \
  -v "$(pwd)/custom-events.json:/input/events.json:ro" \
  securesense:local \
  report --events /input/events.json
```

This uses the device policies bundled in the image. For a different device
configuration directory, mount it into the container and supply
`--devices-dir` with the container path.

## Local MQTT broker

Start the MQTT service with Docker Compose:

```bash
docker compose up -d mqtt
docker compose ps
```

View broker logs:

```bash
docker compose logs mqtt
```

Stop the broker:

```bash
docker compose down
```

The supplied Compose configuration binds the broker to host loopback
(`127.0.0.1:1883`). The sample Mosquitto configuration permits anonymous
connections and is intended only for isolated local development and simulation.
Do not expose this configuration to untrusted networks or use it as a
production security baseline.

## Security detections

The sample investigation demonstrates:

| Rule | Detection | Example |
|---|---|---|
| NET-001 | Unauthorized network communication | A registered device contacts an unapproved destination |
| NET-002 | Unregistered device activity | An event references a device absent from the registry |

The sample scenario also demonstrates risk scoring, incident creation, and
candidate attack-path correlation using a shared IP address.

The example addresses are documentation ranges used for simulation, not
evidence of real devices or an actual intrusion.

## Security boundaries and limitations

- Risk scores use configured severity-based rules; they are not calibrated
  probabilities of compromise.
- Candidate attack paths are correlations that require analyst validation.
- Response actions are recorded as dry-run recommendations and do not block
  traffic, isolate devices, or change network state.
- The sample event scenario is simulated and does not establish real-world
  detection accuracy.
- Anonymous MQTT access is suitable only for isolated local simulation.
- Production deployment would require appropriate broker authentication and
  authorization, transport security, secrets management, deployment hardening,
  operational monitoring, and validation against representative traffic.

## Validation

The latest local validation completed successfully:

- **129 tests passed**
- **Ruff:** all checks passed
- **uv lock check:** completed successfully
- **Docker image:** built successfully
- **Container execution:** sample investigation report generated successfully

These results describe the local validation performed so far. The Wokwi
serial-output replay was verified through the MQTT bridge and a local MQTT
subscriber. Continuous direct Wokwi-to-MQTT streaming is not implemented.
GitHub Actions CI passed for the latest documentation commit [`a61ba25`](https://github.com/SriKrishna40007/SecureSense/actions/runs/38270802624).

## License

See [LICENSE](LICENSE).

## Scenario testing guide

The files in `scenarios/manual-tests/` provide repeatable, synthetic
investigation cases. Run these commands from the repository root.

Create a directory for generated reports:

```bash
mkdir -p reports
```

### 1. Authorized communication

```bash
uv run securesense report \
  --events scenarios/manual-tests/positive-authorized.json \
  --devices-dir devices \
  --output reports/positive-authorized.txt
```

**Purpose:** Verify that a registered device communicating with an
approved destination under its configured policy is allowed.

**Expected result:** No security finding for the authorized event.

### 2. Unauthorized communication

```bash
uv run securesense report \
  --events scenarios/manual-tests/negative-unauthorized.json \
  --devices-dir devices \
  --output reports/negative-unauthorized.txt
```

**Purpose:** Verify that a registered device contacting an unapproved
destination is detected.

**Expected result:** A `NET-001` finding for unauthorized communication.

### 3. Unregistered device accessing an industrial controller

```bash
uv run securesense report \
  --events scenarios/manual-tests/unknown-plc-access.json \
  --devices-dir devices \
  --output reports/unknown-plc-access.txt
```

**Purpose:** Test how the investigation pipeline handles a device that
does not exist in the configured device registry.

**Expected result:** A `NET-002` finding for unregistered device activity.

This is a synthetic, threat-informed scenario. It does not contact a real
industrial controller or reproduce a specific intrusion.

### 4. Candidate lateral movement

```bash
uv run securesense report \
  --events scenarios/manual-tests/candidate-lateral-movement.json \
  --devices-dir devices \
  --output reports/candidate-lateral-movement.txt \
  --recommend-response
```

**Purpose:** Examine whether chronologically related events with shared
network evidence produce a candidate attack-path correlation.

**Expected result:** Candidate path evidence requiring analyst validation.
A shared IP address is a correlation signal, not proof of lateral movement.

### 5. Unrelated events

```bash
uv run securesense report \
  --events scenarios/manual-tests/unrelated-events.json \
  --devices-dir devices \
  --output reports/unrelated-events.txt
```

**Purpose:** Check that unrelated events do not get linked into a candidate
attack path solely because multiple findings exist.

**Expected result:** Findings may still be produced, but no candidate path
should be identified for this scenario.

### Inspect the reports

Open any generated text report in your terminal, for example:

```bash
cat reports/candidate-lateral-movement.txt
```

Review the findings, evidence, risk assessments, incident information,
candidate-path classification, and response audit. Incident identifiers
can vary between separate runs because incident state is maintained in
memory.

These scenarios validate defined application behavior against synthetic
inputs. They do not establish detection accuracy against real industrial
network traffic.

## Project documentation

The documentation below explains how SecureSense was designed, implemented,
validated, and prepared for release.

- [Project build and validation journey](docs/PROJECT_BUILD_AND_VALIDATION.md) —
  original idea, implementation phases, test evidence, lessons learned, and
  remaining release work.
- [Architecture and threat model](docs/ARCHITECTURE_AND_THREAT_MODEL.md) —
  components, data flows, trust boundaries, threat scenarios, and limitations.
- [Release checklist](docs/RELEASE_CHECKLIST.md) — repository review, local
  validation, approval gates, commit and push steps, and hosted CI evidence.

**Release status:** Version `v0.1.0` is published on GitHub.

- Release tag: `v0.1.0`, pointing to commit `b784493`.
- Latest documentation commit: `a61ba25` on `master`.
- Hosted CI: [passed for the latest documentation commit](https://github.com/SriKrishna40007/SecureSense/actions/runs/38270802624).
