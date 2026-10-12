from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class SensorReading:
    device_id: str
    metric: str
    value: float
    unit: str
    timestamp: datetime
