from datetime import UTC, datetime

import pytest

from securesense.domain.attack_paths.correlator import AttackPathCorrelator
from securesense.domain.findings.models import (
    FindingSeverity,
    SecurityFinding,
)


def make_finding(
    *,
    device_id: str,
    source_ip: str,
    destination_ip: str,
    observed_at: datetime,
) -> SecurityFinding:
    return SecurityFinding(
        rule_id="NET-001",
        title="Unauthorized network communication",
        severity=FindingSeverity.HIGH,
        device_id=device_id,
        description="Communication violated the device security policy.",
        evidence={
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "protocol": "tcp",
            "destination_port": 4444,
        },
        recommendation="Investigate the observed communication.",
        observed_at=observed_at,
    )


@pytest.fixture
def correlator() -> AttackPathCorrelator:
    return AttackPathCorrelator()


def test_correlates_findings_with_a_shared_network_hop(
    correlator: AttackPathCorrelator,
) -> None:
    first = make_finding(
        device_id="TEMP-001",
        source_ip="192.0.2.10",
        destination_ip="192.0.2.20",
        observed_at=datetime(2026, 10, 10, 8, 0, tzinfo=UTC),
    )
    second = make_finding(
        device_id="VIB-001",
        source_ip="192.0.2.20",
        destination_ip="192.0.2.30",
        observed_at=datetime(2026, 10, 10, 8, 1, tzinfo=UTC),
    )

    paths = correlator.correlate([second, first])

    assert len(paths) == 1
    assert paths[0].findings == (first, second)
    assert paths[0].shared_ips == ("192.0.2.20",)
    assert "192.0.2.20" in paths[0].rationale


def test_does_not_correlate_unrelated_network_endpoints(
    correlator: AttackPathCorrelator,
) -> None:
    first = make_finding(
        device_id="TEMP-001",
        source_ip="192.0.2.10",
        destination_ip="192.0.2.20",
        observed_at=datetime(2026, 10, 10, 8, 0, tzinfo=UTC),
    )
    second = make_finding(
        device_id="VIB-001",
        source_ip="198.51.100.20",
        destination_ip="198.51.100.30",
        observed_at=datetime(2026, 10, 10, 8, 1, tzinfo=UTC),
    )

    assert correlator.correlate([first, second]) == []


def test_does_not_correlate_events_out_of_chronological_order(
    correlator: AttackPathCorrelator,
) -> None:
    later = make_finding(
        device_id="TEMP-001",
        source_ip="192.0.2.10",
        destination_ip="192.0.2.20",
        observed_at=datetime(2026, 10, 10, 8, 1, tzinfo=UTC),
    )
    earlier = make_finding(
        device_id="VIB-001",
        source_ip="192.0.2.20",
        destination_ip="192.0.2.30",
        observed_at=datetime(2026, 10, 10, 8, 0, tzinfo=UTC),
    )

    assert correlator.correlate([later, earlier]) == []


def test_ignores_findings_without_network_evidence(
    correlator: AttackPathCorrelator,
) -> None:
    first = make_finding(
        device_id="TEMP-001",
        source_ip="192.0.2.10",
        destination_ip="192.0.2.20",
        observed_at=datetime(2026, 10, 10, 8, 0, tzinfo=UTC),
    )
    second = make_finding(
        device_id="VIB-001",
        source_ip="192.0.2.20",
        destination_ip="192.0.2.30",
        observed_at=datetime(2026, 10, 10, 8, 1, tzinfo=UTC),
    )
    second = SecurityFinding(
        rule_id=second.rule_id,
        title=second.title,
        severity=second.severity,
        device_id=second.device_id,
        description=second.description,
        evidence={"protocol": "tcp"},
        recommendation=second.recommendation,
        observed_at=second.observed_at,
    )

    assert correlator.correlate([first, second]) == []
