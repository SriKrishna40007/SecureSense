from dataclasses import dataclass
from enum import StrEnum


class Protocol(StrEnum):
    MQTT = "mqtt"
    TCP = "tcp"
    UDP = "udp"


@dataclass(frozen=True)
class CommunicationPolicy:
    device_id: str
    allowed_protocols: frozenset[Protocol]
    allowed_destinations: frozenset[str]
    allowed_ports: frozenset[int]
    allowed_network_zones: frozenset[str]
