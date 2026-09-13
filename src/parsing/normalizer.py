from pathlib import PurePosixPath

from src.parsing.auth_parser import AuthEvent
from src.parsing.models import SecurityEvent
from src.parsing.ubuntu_auth_parser import UbuntuAuthEvent


COMMAND_ACTIONS = {
    "apt": "PACKAGE_MANAGEMENT",
    "apt-get": "PACKAGE_MANAGEMENT",
    "aptitude": "PACKAGE_MANAGEMENT",
    "grep": "LOG_ANALYSIS",
    "awk": "LOG_ANALYSIS",
    "sed": "TEXT_PROCESSING",
    "tail": "LOG_ANALYSIS",
    "head": "LOG_ANALYSIS",
    "cat": "FILE_READ",
    "less": "FILE_READ",
    "more": "FILE_READ",
    "python": "SCRIPT_EXECUTION",
    "python3": "SCRIPT_EXECUTION",
    "bash": "SHELL_EXECUTION",
    "sh": "SHELL_EXECUTION",
    "systemctl": "SERVICE_MANAGEMENT",
    "chmod": "PERMISSION_CHANGE",
    "chown": "OWNERSHIP_CHANGE",
    "useradd": "ACCOUNT_MANAGEMENT",
    "usermod": "ACCOUNT_MANAGEMENT",
    "userdel": "ACCOUNT_MANAGEMENT",
    "groupadd": "ACCOUNT_MANAGEMENT",
    "groupdel": "ACCOUNT_MANAGEMENT",
    "gpasswd": "ACCOUNT_MANAGEMENT",
    "passwd": "CREDENTIAL_MANAGEMENT",
    "visudo": "SUDO_POLICY_CHANGE",
}


def get_command_name(
    command: str | None,
) -> str | None:
    """Extract executable name from a command."""
    if not command:
        return None

    executable = (
        command.strip()
        .split(maxsplit=1)[0]
    )

    return PurePosixPath(executable).name


def classify_command(
    command: str | None,
) -> str | None:
    """Map a command to a high-level action."""
    command_name = get_command_name(command)

    if command_name is None:
        return None

    return COMMAND_ACTIONS.get(
        command_name,
        "OTHER",
    )


def normalize_synthetic_event(
    event: AuthEvent,
) -> SecurityEvent:
    """Convert synthetic event to SecurityEvent."""
    return SecurityEvent(
        timestamp=event.timestamp,
        event_type=event.event_type,
        username=event.username,
        source_ip=event.source_ip,
        hostname=None,
        service="synthetic-auth",
        command=None,
        command_name=None,
        action=None,
        target_user=None,
        working_directory=None,
        raw_message=(
            f"{event.event_type} "
            f"user={event.username} "
            f"src={event.source_ip}"
        ),
    )


def normalize_ubuntu_event(
    event: UbuntuAuthEvent,
) -> SecurityEvent:
    """Convert Ubuntu event to normalized SecurityEvent."""
    command_name = get_command_name(
        event.command
    )

    action = classify_command(
        event.command
    )

    working_directory = None

    if event.raw_message:
        import re

        pwd_match = re.search(
            r"\bPWD=(.*?)\s*;\s*USER=",
            event.raw_message,
        )

        if pwd_match:
            working_directory = (
                pwd_match.group(1)
            )

    return SecurityEvent(
        timestamp=event.timestamp,
        event_type=event.event_type,
        username=event.username,
        source_ip=event.source_ip,
        hostname=event.hostname,
        service=event.service,
        command=event.command,
        command_name=command_name,
        action=action,
        target_user=event.target_user,
        working_directory=working_directory,
        raw_message=event.raw_message,
    )
