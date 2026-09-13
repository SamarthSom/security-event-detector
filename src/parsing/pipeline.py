from src.ingestion.reader import read_log_file
from src.parsing.auth_parser import AuthEvent, parse_auth_line
from src.parsing.models import SecurityEvent
from src.parsing.normalizer import (
    normalize_synthetic_event,
    normalize_ubuntu_event,
)
from src.parsing.ubuntu_auth_parser import (
    UbuntuAuthEvent,
    parse_ubuntu_auth_line,
)


def parse_auth_file(path: str) -> list[AuthEvent]:
    """Backward-compatible synthetic parser."""
    return parse_synthetic_auth_file(path)


def parse_synthetic_auth_file(path: str) -> list[AuthEvent]:
    """Parse the project's synthetic authentication log format."""
    lines = read_log_file(path)

    events = []

    for line in lines:
        event = parse_auth_line(line)

        if event is not None:
            events.append(event)

    return events


def parse_ubuntu_auth_file(path: str) -> list[UbuntuAuthEvent]:
    """Parse an Ubuntu auth.log file."""
    lines = read_log_file(path)

    events = []

    for line in lines:
        event = parse_ubuntu_auth_line(line)

        if event is not None:
            events.append(event)

    return events


def resemblances_to_ubuntu(line: str) -> bool:
    """Return True when a line resembles Ubuntu auth.log syntax."""
    return (
        len(line) >= 25
        and "T" in line[:25]
        and "+" in line[:30]
        and " " in line
        and ":" in line
    )


def detect_log_format(path: str) -> str:
    """Detect whether a file uses the synthetic or Ubuntu auth format."""
    lines = read_log_file(path)

    for line in lines[:20]:
        if "SSH_LOGIN_" in line and "src=" in line:
            return "synthetic"

        if resemblances_to_ubuntu(line):
            return "ubuntu"

    raise ValueError("Could not determine the log format.")


def parse_file(path: str) -> list[SecurityEvent]:
    """Parse and normalize a supported log file."""
    log_format = detect_log_format(path)

    if log_format == "synthetic":
        events = parse_synthetic_auth_file(path)
        return [
            normalize_synthetic_event(event)
            for event in events
        ]

    if log_format == "ubuntu":
        events = parse_ubuntu_auth_file(path)
        return [
            normalize_ubuntu_event(event)
            for event in events
        ]

    raise ValueError(
        f"Unsupported log format: {log_format}"
    )
