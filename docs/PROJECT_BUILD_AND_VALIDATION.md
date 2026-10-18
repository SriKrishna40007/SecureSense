# SecureSense: Project Build and Validation Journey

## 1. Purpose of this document

This document records the engineering journey behind SecureSense, from the
original problem statement through architecture, implementation, testing,
demonstration, and release preparation.

It distinguishes implemented capabilities from validated results and work
that remains unverified. It is intended for technical interviews, portfolio
reviews, project maintenance, and future development.

## 2. Original idea and engineering objective

SecureSense was conceived as an Industrial IoT Cloud Security and Threat
Detection Platform.

Industrial environments can contain sensors, controllers, gateways, and
other devices whose communications must be constrained and investigated.
Unexpected destinations, unknown devices, and relationships between network
events can be useful signals for a security analyst.

The project objective was to build a practical, demonstrable security
engineering system that could:

- Represent industrial IoT devices and their communication policies.
- Validate and investigate structured network-event data.
- Detect unauthorized communication and activity from unregistered devices.
- Assign explainable, severity-based risk scores.
- Create and track security incidents.
- Correlate network evidence into candidate attack paths.
- Record auditable response recommendations without changing network state.
- Demonstrate IoT telemetry through a virtual sensor and MQTT workflow.
- Provide a CLI, REST API, automated tests, containerization, and CI configuration.

The implementation uses synthetic event data and a virtual IoT device. It is
a portfolio engineering project, not a production-certified security product.

## 3. Scope and engineering principles

The project prioritizes practical implementation, repeatable validation,
clear evidence, and a small set of integrated capabilities.

The engineering principles are:

1. **Explicit policies:** Device communication is evaluated against configured
   device identity and communication rules.
2. **Evidence-backed findings:** Findings retain information that explains
   why an event was considered suspicious.
3. **Explainable risk:** Risk scores are derived from configured severity
   rules; they are not probabilities of compromise.
4. **Conservative correlation:** A candidate attack path is a hypothesis for
   investigation, not proof of an intrusion.
5. **Auditable response:** Recommendations are recorded in dry-run mode and
   do not block traffic or isolate devices.
6. **Testability:** Domain logic, input validation, API behavior, and reporting
   have automated tests.
7. **Honest boundaries:** Simulation, in-memory state, and unverified release
   steps are documented rather than presented as production capabilities.

## 4. Architecture and implementation journey

### Phase 1 — Device models and configuration

Device models, network zones, communication policies, YAML configuration
loading, and a device registry establish the foundation for representing
known IoT devices.

The registry provides the device inventory used during policy evaluation.
Configuration files define the devices and the communication rules used by
the sample scenarios.

### Phase 2 — Policy evaluation and detection

The policy evaluator checks network-event attributes against configured
communication rules, including protocol, destination, port, and network zone.

The investigation workflow produces two principal detection types:

- `NET-001`: Unauthorized network communication.
- `NET-002`: Network activity from an unregistered device.

Findings preserve evidence and recommendations so that an analyst can
understand the decision rather than receiving only a generic alert.

### Phase 3 — Risk and incident lifecycle

Findings feed a severity-based risk scorer and incident service. Incidents
have identifiers, an initial open state, and supported lifecycle transitions
with audit history.

The sample high-severity findings receive a configured risk score of 70/100.
This score is a rule-based assessment, not a calibrated probability.

Incident state and lifecycle audit history are persisted in SQLite. Local verification confirmed that saved investigations and sensor readings remain available after an API restart.

### Phase 4 — Candidate attack-path correlation

The correlator examines network evidence and event ordering to identify
candidate relationships between findings.

The lateral-movement scenario uses a shared IP address as a possible network
hop between two events. The unrelated-events scenario checks that unrelated
endpoints do not produce a candidate path.

These results are investigative leads. They do not establish attacker
identity, intent, or confirmed lateral movement.

### Phase 5 — Auditable response recommendations

The response service can record recommendations associated with incidents.
The CLI supports `--recommend-response` to include dry-run recommendations
in an investigation.

Dry-run means that the recommendation is recorded but not executed. SecureSense
does not use this workflow to block network traffic, isolate devices, or
modify external systems.

### Phase 6 — CLI and investigation reports

The Typer-based CLI provides report generation and an MQTT telemetry listener.

The report workflow accepts JSON network events, loads device configuration,
evaluates events, and produces a report containing the executive summary,
findings, evidence, risk assessments, incidents, candidate paths, response
audit, and limitations.

Example:

```bash
uv run securesense report \
  --events scenarios/events/investigation.json \
  --devices-dir devices \
  --output reports/investigation-report.txt
```

Create the output directory first if it does not exist:

```bash
mkdir -p reports
```

### Phase 7 — Virtual IoT and MQTT demonstration

The virtual IoT workflow uses an ESP32 and DHT22 sensor in Wokwi. The firmware
emits temperature readings over the serial interface. A Python serial bridge
parses valid readings and publishes JSON telemetry to an MQTT topic.

The local replay demonstration was verified through the bridge and an MQTT
subscriber.

**Boundary:** Continuous direct streaming from the Wokwi simulation into the
MQTT broker has not been implemented. The sensor/MQTT workflow and the JSON
network-event investigation workflow are separate capabilities; MQTT sensor
readings are not automatically converted into network-security events.

The local Mosquitto configuration is intended for isolated simulation only.
Its anonymous access must not be exposed to untrusted networks.

### Phase 8 — REST API

The FastAPI application exposes:

- `GET /health` — API health check.
- `GET /devices` — configured device inventory.
- `POST /investigations` — investigation of a supplied network-event batch.

The API runs on localhost in the documented development command. It accepts
validated JSON events and returns investigation results.

The dedicated MQTT network-event subscriber automatically passes valid network events into the investigation pipeline. Sensor telemetry remains separate and is not automatically converted into network events. Incident and investigation data are persisted in SQLite. Response actions are not executed; recommendations remain dry-run only.

### Phase 9 — Docker and CI configuration

The project includes a Docker image and Docker Compose configuration for
local development. The image build and bundled sample report execution were
verified locally. The image runs as a non-root user.

A GitHub Actions workflow is configured to install locked dependencies, run
Ruff, and execute the test suite. The hosted workflow has not yet been
verified on GitHub because the repository has not been pushed as part of this
release process.

## 5. Manual scenario validation

Five synthetic scenarios were executed through the CLI.

| Scenario | Observed result | What it validates |
|---|---|---|
| `positive-authorized.json` | 1 event, 0 findings, 0 incidents | Expected communication is allowed |
| `negative-unauthorized.json` | 1 finding, 1 incident, high severity | Unauthorized communication produces `NET-001` |
| `unknown-plc-access.json` | 1 finding, 1 incident, high severity | An unregistered device produces `NET-002` |
| `candidate-lateral-movement.json` | 2 findings, 2 incidents, 1 candidate path | Shared network evidence can be correlated |
| `unrelated-events.json` | 2 findings, 2 incidents, 0 candidate paths | Unrelated endpoints are not linked by this correlation rule |

Run the scenarios from the repository root:

```bash
mkdir -p reports

uv run securesense report \
  --events scenarios/manual-tests/positive-authorized.json \
  --devices-dir devices \
  --output reports/positive-authorized.txt

uv run securesense report \
  --events scenarios/manual-tests/negative-unauthorized.json \
  --devices-dir devices \
  --output reports/negative-unauthorized.txt

uv run securesense report \
  --events scenarios/manual-tests/unknown-plc-access.json \
  --devices-dir devices \
  --output reports/unknown-plc-access.txt

uv run securesense report \
  --events scenarios/manual-tests/candidate-lateral-movement.json \
  --devices-dir devices \
  --output reports/candidate-lateral-movement.txt \
  --recommend-response

uv run securesense report \
  --events scenarios/manual-tests/unrelated-events.json \
  --devices-dir devices \
  --output reports/unrelated-events.txt
```

All five commands completed successfully during local validation. Their
incident identifiers are generated per application invocation and may differ
between runs. The IP addresses are documentation ranges used for simulation;
no real industrial controller was contacted.

## 6. Automated validation evidence

The latest recorded local validation after the documentation updates reported:

- **Pytest:** 211 passed, 1 deprecation warning in the latest recorded full run.
- **Ruff:** all checks passed.
- **Dependency lock:** `uv lock --check` completed successfully.
- **Manual scenarios:** all five documented CLI scenarios completed.
- **Docker:** image build and bundled sample execution were verified earlier.
- **MQTT:** Wokwi serial-output replay through the MQTT bridge and a local
  subscriber was verified earlier.

The test warning concerns use of `httpx` with Starlette's test client. It did
not cause a test failure. Dependency compatibility should be reviewed in a
separate change.

The Docker and MQTT statements describe earlier recorded checks; they were
not rerun by the latest pytest command.

## 7. Security boundaries and limitations

SecureSense currently has the following limitations:

- Sample network events are synthetic and do not establish real-world
  detection accuracy.
- Risk scores are configured severity-based scores, not probabilities.
- Candidate attack paths require analyst validation.
- Response recommendations are dry-run records, not enforcement actions.
- Incident and investigation data, lifecycle audit history, sensor readings, and event-deduplication records are persisted in SQLite; API restart persistence has been verified locally.
- MQTT sensor telemetry is not automatically translated into network-security events; the dedicated network-event topic has its own investigation workflow.
- The local MQTT broker requires authentication, but the setup does not provide TLS and is not a production or internet-facing security baseline.
- Hosted CI must be verified for the eventual approved commit; historical CI success does not verify current uncommitted changes.

A production-oriented deployment would require, at minimum, authenticated and
authorized broker access, transport security, secrets management, hardened
deployment configuration, durable state where required, operational monitoring,
and validation using representative authorized traffic.

## 8. Release history and remaining work

### Completed locally

- Core device, policy, detection, risk, incident, correlation, and response
  workflows implemented.
- CLI, REST API, sample scenarios, automated tests, Docker, and virtual IoT
  demonstration implemented.
- Five manual investigation scenarios executed successfully.
- README and this engineering-history document prepared.
- Latest recorded test suite, Ruff checks, and dependency-lock check passed.

### Pending release evidence

- Review the final repository status and all intended files.
- Review the staged diff before creating a commit.
- Commit only after explicit approval.
- Push to the intended GitHub repository only after explicit approval.
- Verify the hosted GitHub Actions workflow and record the result.
- Record the actual commit identifier, push result, and release tag if one is
  created.

No commit, push, or hosted CI success is claimed by this document.

## 9. Lessons learned

- Separate sensor telemetry from network-security events unless an explicit,
  validated integration connects them.
- Preserve the evidence behind security findings and correlation decisions.
- Treat correlations as hypotheses rather than confirmed attacks.
- Keep response recommendations auditable and non-executing until safe,
  authorized enforcement is deliberately designed.
- Verify documentation commands against the actual CLI and request schemas.
- Distinguish successful local checks from hosted CI and release verification.

## 10. Further reading

- [Project README](../README.md)
- [Architecture and threat model](ARCHITECTURE_AND_THREAT_MODEL.md)
- [Release checklist](RELEASE_CHECKLIST.md)
