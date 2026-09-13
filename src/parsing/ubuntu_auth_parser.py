from dataclasses import dataclass
from datetime import datetime
import re


@dataclass(frozen=True)
class UbuntuAuthEvent:
    timestamp: datetime
    hostname: str
    service: str
    username: str | None
    command: str | None
    target_user: str | None
    source_ip: str | None
    event_type: str
    raw_message: str


HEADER_PATTERN = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2}T[^ ]+)\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<service>[A-Za-z0-9_.-]+)"
    r"(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<message>.*)$"
)

SUDO_PATTERN = re.compile(
    r"sudo:\s+(?P<user>\S+)\s*:.*?"
    r"USER=(?P<target_user>\S+)\s*;"
    r".*?COMMAND=(?P<command>.*)$"
)

FAILED_SSH_PATTERN = re.compile(
    r"Failed password for "
    r"(?:invalid user )?"
    r"(?P<user>[A-Za-z0-9_.-]+)\s+"
    r"from\s+(?P<source_ip>[0-9A-Fa-f:.]+)"
)

SUCCESSFUL_SSH_PATTERN = re.compile(
    r"Accepted (?:password|publickey) for "
    r"(?P<user>[A-Za-z0-9_.-]+)\s+"
    r"from\s+(?P<source_ip>[0-9A-Fa-f:.]+)"
)


def parse_ubuntu_auth_line(
    line: str,
) -> UbuntuAuthEvent | None:
    """Parse one Ubuntu auth.log line."""
    line = line.strip()

    if not line:
        return None

    match = HEADER_PATTERN.match(line)

    if not match:
        return None

    timestamp = datetime.fromisoformat(
        match.group("timestamp")
    )

    hostname = match.group("hostname")
    service = match.group("service")
    message = match.group("message")

    username = None
    command = None
    target_user = None
    source_ip = None

    event_type = (
        f"UBUNTU_{service.upper()}"
    )

    sudo_match = SUDO_PATTERN.search(line)

    if sudo_match:
        username = sudo_match.group("user")
        command = sudo_match.group("command")
        target_user = sudo_match.group("target_user")
        event_type = "UBUNTU_SUDO"

    failed_ssh_match = FAILED_SSH_PATTERN.search(
        message
    )

    if (
        failed_ssh_match
        and service == "sshd"
    ):
        username = failed_ssh_match.group("user")
        source_ip = failed_ssh_match.group("source_ip")
        event_type = "SSH_LOGIN_FAILED"

    successful_ssh_match = SUCCESSFUL_SSH_PATTERN.search(
        message
    )

    if (
        successful_ssh_match
        and service == "sshd"
    ):
        username = successful_ssh_match.group("user")
        source_ip = successful_ssh_match.group("source_ip")
        event_type = "SSH_LOGIN_SUCCESS"

    if (
        username is None
        and message
    ):
        session_match = re.search(
            r"user\s+'?([A-Za-z0-9_.-]+)'?",
            message,
        )

        if session_match:
            username = session_match.group(1)

    return UbuntuAuthEvent(
        timestamp=timestamp,
        hostname=hostname,
        service=service,
        username=username,
        command=command,
        target_user=target_user,
        source_ip=source_ip,
        event_type=event_type,
        raw_message=message,
    )
