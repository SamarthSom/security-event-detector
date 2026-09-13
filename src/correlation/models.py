from dataclasses import dataclass
from datetime import datetime

from src.detection.models import Detection
from src.parsing.models import SecurityEvent


@dataclass(frozen=True)
class TimelineEvent:
    timestamp: datetime
    event_type: str
    username: str | None
    source_ip: str | None
    service: str | None
    command: str | None
    action: str | None


@dataclass(frozen=True)
class Incident:
    incident_id: str
    severity: str
    source_ip: str | None
    start_time: datetime
    end_time: datetime
    detections: tuple[Detection, ...]
    timeline: tuple[TimelineEvent, ...]
    summary: str
