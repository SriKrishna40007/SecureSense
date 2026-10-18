# SecureSense Integration Contract

Version: 1.0

## Purpose

SecureSense separates sensor telemetry from network-security-event workflows. Never infer IP addresses, ports, or protocols from sensor measurements.

## Local deployment

- Dashboard and API: http://127.0.0.1:8001
- Local MQTT broker: 127.0.0.1:1883
- Store SECURESENSE_API_TOKEN in the ignored local .env file.
- Production mode requires an API token at least 32 characters long.
- Protected REST requests use Authorization: Bearer <token>.

## Sensor telemetry

Publish readings to securesense/devices/{device_id}/telemetry. The topic device ID must match the payload device_id. Only registered devices are persisted.

Example payload:

    {
      "device_id": "TEMP-001",
      "metric": "temperature",
      "value": 26.4,
      "unit": "celsius",
      "timestamp": "2026-10-17T05:06:07+00:00"
    }

## Network security events

The separate network-event subscriber uses securesense/network-events. Example payload:

    {
      "event_id": "demo-event-0001",
      "device_id": "TEMP-001",
      "source_ip": "192.0.2.10",
      "destination": "example-service",
      "destination_ip": "192.0.2.20",
      "protocol": "tcp",
      "destination_port": 443,
      "network_zone": "iot",
      "timestamp": "2026-10-17T05:06:07+00:00"
    }

The IP addresses are documentation examples. The dedicated MQTT network-event subscriber validates messages published to `securesense/network-events` and automatically passes valid events into the investigation pipeline. Sensor telemetry uses its separate topic and is not automatically converted into network-security events. Duplicate event IDs are deduplicated.

## REST API

- GET /health — health check.
- GET /devices — registered devices.
- GET /telemetry/latest — latest persisted readings.
- GET /telemetry/readings?limit=100 — reading history; limit must be 1–5000.
- POST /investigations — submit network events for investigation.
- GET /investigations — list saved investigations.
- GET /investigations/{id} — retrieve a saved investigation.

Use bearer authentication for protected endpoints. Check the running API for the exact request schema.

## Persistence and safety

SQLite persists investigations, incidents and lifecycle audit history, sensor readings, and event-deduplication records. Docker Compose mounts the local `.data` directory for database persistence. Keep `.env` and API tokens private. Candidate attack paths require analyst validation; automated response actions are not executed. The local MQTT broker is configured for authenticated access, but this lab setup does not provide TLS and must not be exposed directly to the internet.

## Example client

See examples/integration_client.py for a reusable Python client.
