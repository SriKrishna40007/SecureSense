from dataclasses import dataclass
from datetime import datetime

from securesense.domain.policies.models import Protocol


@dataclass(frozen=True)
class NetworkEvent:
    device_id: str
    source_ip: str
    destination: str
    destination_ip: str
    protocol: Protocol
    destination_port: int
    network_zone: str
    timestamp: datetime
