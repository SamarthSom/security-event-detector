from collections import defaultdict
from datetime import timedelta
from pathlib import PurePosixPath

from src.detection.models import Detection
from src.parsing.models import SecurityEvent


def detect_brute_force(
    events: list[SecurityEvent],
    threshold: int = 5,
    window_seconds: int = 60,
) -> list[Detection]:
    """Detect repeated failed authentication attempts from one IP."""
    failed_by_ip = defaultdict(list)

    for event in events:
        if (
            event.event_type == "SSH_LOGIN_FAILED"
            and event.source_ip is not None
        ):
            failed_by_ip[event.source_ip].append(event)

    detections = []

    for source_ip, failures in failed_by_ip.items():
        failures.sort(key=lambda event: event.timestamp)

        for index, start_event in enumerate(failures):
            window_end = (
                start_event.timestamp
                + timedelta(seconds=window_seconds)
            )

            window_events = [
                event
                for event in failures[index:]
                if event.timestamp <= window_end
            ]

            if len(window_events) >= threshold:
                detections.append(
                    Detection(
                        rule_id="AUTH-001",
                        name="SSH Brute-Force Pattern",
                        severity="HIGH",
                        source_ip=source_ip,
                        description=(
                            f"{len(window_events)} failed SSH "
                            f"authentication attempts from "
                            f"{source_ip} within "
                            f"{window_seconds} seconds."
                        ),
                        evidence=tuple(window_events),
                        detected_at=window_events[-1].timestamp,
                    )
                )
                break

    return detections


def detect_password_spray(
    events: list[SecurityEvent],
    account_threshold: int = 4,
    window_seconds: int = 60,
) -> list[Detection]:
    """Detect one IP attempting authentication against many accounts."""
    failed_by_ip = defaultdict(list)

    for event in events:
        if (
            event.event_type == "SSH_LOGIN_FAILED"
            and event.source_ip is not None
            and event.username is not None
        ):
            failed_by_ip[event.source_ip].append(event)

    detections = []

    for source_ip, failures in failed_by_ip.items():
        failures.sort(key=lambda event: event.timestamp)

        for index, start_event in enumerate(failures):
            window_end = (
                start_event.timestamp
                + timedelta(seconds=window_seconds)
            )

            window_events = [
                event
                for event in failures[index:]
                if event.timestamp <= window_end
            ]

            accounts = {
                event.username
                for event in window_events
                if event.username is not None
            }

            if len(accounts) >= account_threshold:
                detections.append(
                    Detection(
                        rule_id="AUTH-002",
                        name="Multi-Account Authentication Pattern",
                        severity="HIGH",
                        source_ip=source_ip,
                        description=(
                            f"{source_ip} attempted authentication "
                            f"against {len(accounts)} different "
                            f"accounts within {window_seconds} seconds."
                        ),
                        evidence=tuple(window_events),
                        detected_at=window_events[-1].timestamp,
                    )
                )
                break

    return detections


def _command_name(command: str) -> str:
    """Return the executable name from a command path."""
    executable = command.strip().split(maxsplit=1)[0]
    return PurePosixPath(executable).name


def detect_sensitive_sudo(
    events: list[SecurityEvent],
) -> list[Detection]:
    """Detect privileged commands with security-sensitive actions."""
    sensitive_actions = {
        "PERMISSION_CHANGE",
        "OWNERSHIP_CHANGE",
        "ACCOUNT_MANAGEMENT",
        "CREDENTIAL_MANAGEMENT",
        "SUDO_POLICY_CHANGE",
        "SERVICE_MANAGEMENT",
    }

    detections = []

    for event in events:
        if (
            event.event_type == "UBUNTU_SUDO"
            and event.action in sensitive_actions
        ):
            command_name = event.command_name or (
                _command_name(event.command)
                if event.command
                else "unknown"
            )

            detections.append(
                Detection(
                    rule_id="SUDO-001",
                    name="Sensitive Privileged Execution",
                    severity="MEDIUM",
                    source_ip=None,
                    description=(
                        f"User {event.username or 'unknown'} executed "
                        f"{command_name} as "
                        f"{event.target_user or 'unknown'} "
                        f"({event.action})."
                    ),
                    evidence=(event,),
                    detected_at=event.timestamp,
                )
            )

    return detections


def detect_privileged_burst(
    events: list[SecurityEvent],
    threshold: int = 3,
    window_seconds: int = 60,
) -> list[Detection]:
    """Detect a burst of security-sensitive privileged commands."""
    relevant = [
        event
        for event in events
        if (
            event.event_type == "UBUNTU_SUDO"
            and event.action in {
                "PERMISSION_CHANGE",
                "OWNERSHIP_CHANGE",
                "ACCOUNT_MANAGEMENT",
                "CREDENTIAL_MANAGEMENT",
                "SUDO_POLICY_CHANGE",
                "SERVICE_MANAGEMENT",
            }
        )
    ]

    relevant.sort(key=lambda event: event.timestamp)

    detections = []

    for index, start_event in enumerate(relevant):
        window_end = (
            start_event.timestamp
            + timedelta(seconds=window_seconds)
        )

        window_events = [
            event
            for event in relevant[index:]
            if event.timestamp <= window_end
        ]

        distinct_actions = {
            event.action
            for event in window_events
        }

        if (
            len(window_events) >= threshold
            and len(distinct_actions) >= 2
        ):
            detections.append(
                Detection(
                    rule_id="SUDO-002",
                    name="Privileged Activity Burst",
                    severity="HIGH",
                    source_ip=None,
                    description=(
                        f"{len(window_events)} security-sensitive "
                        f"privileged commands were executed within "
                        f"{window_seconds} seconds across "
                        f"{len(distinct_actions)} action categories."
                    ),
                    evidence=tuple(window_events),
                    detected_at=window_events[-1].timestamp,
                )
            )
            break

    return detections
