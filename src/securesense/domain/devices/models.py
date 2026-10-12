from dataclasses import dataclass
from enum import StrEnum


class DeviceType(StrEnum):
    TEMPERATURE_SENSOR = "temperature_sensor"
    VIBRATION_SENSOR = "vibration_sensor"
    PRESSURE_SENSOR = "pressure_sensor"


class NetworkZone(StrEnum):
    IOT = "iot"
    APPLICATION = "application"
    SENSITIVE = "sensitive"


@dataclass(frozen=True)
class Device:
    device_id: str
    device_type: DeviceType
    purpose: str
    network_zone: NetworkZone
