from dataclasses import dataclass

from securesense.domain.devices.models import Device
from securesense.domain.policies.models import CommunicationPolicy


@dataclass(frozen=True)
class RegisteredDevice:
    device: Device
    policy: CommunicationPolicy


class DeviceRegistry:
    def __init__(self) -> None:
        self._devices: dict[str, RegisteredDevice] = {}

    def register(
        self,
        device: Device,
        policy: CommunicationPolicy,
    ) -> None:
        if device.device_id in self._devices:
            raise ValueError(
                f"Device '{device.device_id}' is already registered"
            )

        if policy.device_id != device.device_id:
            raise ValueError(
                "Device and policy identifiers must match"
            )

        self._devices[device.device_id] = RegisteredDevice(
            device=device,
            policy=policy,
        )

    def get(self, device_id: str) -> RegisteredDevice:
        try:
            return self._devices[device_id]
        except KeyError as error:
            raise KeyError(
                f"Device '{device_id}' is not registered"
            ) from error

    def list_devices(self) -> list[RegisteredDevice]:
        return list(self._devices.values())
