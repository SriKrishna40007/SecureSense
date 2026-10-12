"""Conservatively correlate findings using explicit network evidence."""

from collections.abc import Sequence
from ipaddress import ip_address

from securesense.domain.attack_paths.models import AttackPath
from securesense.domain.findings.models import SecurityFinding


class AttackPathCorrelator:
    """Build candidate paths from chronological IP endpoint relationships."""

    @staticmethod
    def _valid_ip(value: object) -> str | None:
        """Return a normalized IP address, or None for invalid evidence."""
        if not isinstance(value, str):
            return None

        try:
            return str(ip_address(value))
        except ValueError:
            return None

    def correlate(
        self,
        findings: Sequence[SecurityFinding],
    ) -> list[AttackPath]:
        """Correlate pairs when an earlier destination matches a later source."""
        ordered = sorted(findings, key=lambda item: item.observed_at)
        paths: list[AttackPath] = []

        for index, first in enumerate(ordered):
            first_destination = self._valid_ip(
                first.evidence.get("destination_ip")
            )
            if first_destination is None:
                continue

            for second in ordered[index + 1 :]:
                second_source = self._valid_ip(
                    second.evidence.get("source_ip")
                )
                if second_source != first_destination:
                    continue

                paths.append(
                    AttackPath(
                        findings=(first, second),
                        shared_ips=(first_destination,),
                        rationale=(
                            f"Earlier finding {first.rule_id} records a "
                            f"destination of {first_destination}; later "
                            f"finding {second.rule_id} records that same "
                            "address as its source. This is a candidate "
                            "network relationship requiring investigation."
                        ),
                        observed_start=first.observed_at,
                        observed_end=second.observed_at,
                    )
                )

        return paths
