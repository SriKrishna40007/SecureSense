from pathlib import Path

import yaml

from securesense.domain.devices.models import Device, DeviceType, NetworkZone
from securesense.domain.policies.models import CommunicationPolicy, Protocol


class DeviceConfigurationLoader:
    def load(
        self,
        file_path: str | Path,
    ) -> tuple[Device, CommunicationPolicy]:
        path = Path(file_path)

        with path.open("r", encoding="utf-8") as file:
            configuration = yaml.safe_load(file)

        device = Device(
            device_id=configuration["device_id"],
            device_type=DeviceType(configuration["device_type"]),
            purpose=configuration["purpose"],
            network_zone=NetworkZone(configuration["network_zone"]),
        )

        policy_configuration = configuration["security_policy"]

        policy = CommunicationPolicy(
            device_id=device.device_id,
            allowed_protocols=frozenset(
                Protocol(protocol)
                for protocol in policy_configuration["allowed_protocols"]
            ),
            allowed_destinations=frozenset(
                policy_configuration["allowed_destinations"]
            ),
            allowed_ports=frozenset(
                policy_configuration["allowed_ports"]
            ),
            allowed_network_zones=frozenset(
                policy_configuration["allowed_network_zones"]
            ),
        )

        return device, policy
