from dataclasses import dataclass
from datetime import datetime
import re


@dataclass(frozen=True)
class AuthEvent:
    timestamp: datetime
    event_type: str
    username: str
    source_ip: str


LOG_PATTERN = re.compile(
    r"^(?P<timestamp>\S+ \S+)\s+"
    r"(?P<event_type>\S+)\s+"
    r"user=(?P<username>\S+)\s+"
    r"src=(?P<source_ip>\S+)$"
)


def parse_auth_line(line: str) -> AuthEvent | None:
    """Convert one structured authentication log line into an AuthEvent."""
    line = line.strip()

    if not line:
        return None

    match = LOG_PATTERN.match(line)

    if not match:
        return None

    timestamp = datetime.strptime(
        match.group("timestamp"),
        "%Y-%m-%d %H:%M:%S",
    )

    return AuthEvent(
        timestamp=timestamp,
        event_type=match.group("event_type"),
        username=match.group("username"),
        source_ip=match.group("source_ip"),
    )
