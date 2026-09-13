from dataclasses import dataclass
from datetime import datetime
from enum import Enum


class IncidentStatus(str, Enum):
    NEW = "NEW"
    OPEN = "OPEN"
    INVESTIGATING = "INVESTIGATING"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


@dataclass(frozen=True)
class IncidentStatusChange:
    status: IncidentStatus
    changed_at: datetime
    note: str = ""
