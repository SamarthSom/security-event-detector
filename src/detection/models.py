from dataclasses import dataclass
from datetime import datetime

from src.parsing.models import SecurityEvent


@dataclass(frozen=True)
class Detection:
    rule_id: str
    name: str
    severity: str
    source_ip: str | None
    description: str
    evidence: tuple[SecurityEvent, ...]
    detected_at: datetime
