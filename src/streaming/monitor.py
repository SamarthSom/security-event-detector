from collections.abc import Callable

from src.correlation.models import Incident
from src.ingestion.follower import follow_file
from src.parsing.normalizer import normalize_ubuntu_event
from src.parsing.ubuntu_auth_parser import parse_ubuntu_auth_line
from src.streaming.correlator import StreamingIncidentCorrelator
from src.streaming.detector import RollingDetector, StreamAlert


def follow_ubuntu_log(
    path: str,
    detector: RollingDetector,
    output_callback: Callable[[StreamAlert], None] | None = None,
    incident_callback: Callable[[Incident], None] | None = None,
    correlator: StreamingIncidentCorrelator | None = None,
) -> None:
    """Follow an Ubuntu auth log and produce correlated incidents."""
    incident_correlator = (
        correlator
        or StreamingIncidentCorrelator(
            window_seconds=detector.window_seconds
        )
    )

    for line in follow_file(path):
        event = parse_ubuntu_auth_line(line)

        if event is None:
            continue

        normalized = normalize_ubuntu_event(
            event
        )

        alerts = detector.process(
            normalized
        )

        for alert in alerts:
            correlated = incident_correlator.process(
                alert.detection
            )

            if correlated is None:
                continue

            incident = correlated.incident

            if incident_callback is not None:
                incident_callback(incident)
            elif output_callback is not None:
                output_callback(alert)
            else:
                _print_incident(incident)


def _print_incident(
    incident: Incident,
) -> None:
    from src.investigation.assessor import assess_incident
    from src.scoring.engine import calculate_risk

    risk = calculate_risk(incident)
    investigation = assess_incident(
        incident
    )

    print()
    print("=== SECURITY INCIDENT ===")
    print(
        f"ID: {incident.incident_id}"
    )
    print(
        f"Severity: {risk.severity}"
    )
    print(
        f"Risk: {risk.score}/100"
    )
    print(
        f"Confidence: {risk.confidence}"
    )
    print(
        f"Source IP: "
        f"{incident.source_ip or 'N/A'}"
    )

    print()
    print("Finding:")
    print(
        f"  {investigation.finding}"
    )

    print()
    print("Rationale:")
    print(
        f"  {investigation.rationale}"
    )

    print()
    print("Detection rules:")

    for detection in incident.detections:
        print(
            f"  - {detection.rule_id}: "
            f"{detection.name}"
        )

    print()
    print("Recommended investigation:")

    for action in (
        investigation.recommended_actions
    ):
        print(
            f"  - {action}"
        )

    print()
    print("=========================")
    print()
