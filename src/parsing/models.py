from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class SecurityEvent:
    timestamp: datetime
    event_type: str
    username: str | None
    source_ip: str | None
    hostname: str | None
    service: str | None
    command: str | None
    command_name: str | None
    action: str | None
    target_user: str | None
    working_directory: str | None
    raw_message: str
