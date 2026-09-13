from collections import defaultdict
from datetime import timedelta

from src.correlation.models import Incident, TimelineEvent
from src.detection.models import Detection


def _correlation_key(detection: Detection) -> str:
    """Choose a stable key for grouping related detections."""
    if detection.source_ip:
        return f"ip:{detection.source_ip}"

    if detection.evidence:
        first_event = detection.evidence[0]

        if first_event.hostname and first_event.username:
            return (
                f"user:{first_event.hostname}:{first_event.username}"
            )

        if first_event.hostname:
            return f"host:{first_event.hostname}"

    return f"rule:{detection.rule_id}"


def correlate_detections(
    detections: list[Detection],
    window_seconds: int = 120,
) -> list[Incident]:
    """Group related detections into incidents."""
    grouped: dict[str, list[Detection]] = defaultdict(list)

    for detection in detections:
        grouped[_correlation_key(detection)].append(detection)

    incidents = []
    incident_number = 1

    for correlation_key, source_detections in grouped.items():
        source_detections.sort(
            key=lambda detection: detection.detected_at
        )

        current_group: list[Detection] = []

        for detection in source_detections:
            if not current_group:
                current_group.append(detection)
                continue

            previous = current_group[-1]

            if (
                detection.detected_at - previous.detected_at
                <= timedelta(seconds=window_seconds)
            ):
                current_group.append(detection)
            else:
                incidents.append(
                    _build_incident(
                        incident_number,
                        correlation_key,
                        current_group,
                    )
                )

                incident_number += 1
                current_group = [detection]

        if current_group:
            incidents.append(
                _build_incident(
                    incident_number,
                    correlation_key,
                    current_group,
                )
            )

            incident_number += 1

    return sorted(
        incidents,
        key=lambda incident: incident.start_time,
        reverse=True,
    )


def _build_incident(
    incident_number: int,
    correlation_key: str,
    detections: list[Detection],
) -> Incident:
    severity_order = {
        "CRITICAL": 4,
        "HIGH": 3,
        "MEDIUM": 2,
        "LOW": 1,
    }

    highest_severity = max(
        detections,
        key=lambda detection: severity_order.get(
            detection.severity,
            0,
        ),
    )

    evidence = [
        event
        for detection in detections
        for event in detection.evidence
    ]

    evidence.sort(key=lambda event: event.timestamp)

    start_time = evidence[0].timestamp
    end_time = evidence[-1].timestamp

    source_ip = next(
        (
            detection.source_ip
            for detection in detections
            if detection.source_ip
        ),
        None,
    )

    timeline = tuple(
        TimelineEvent(
            timestamp=event.timestamp,
            event_type=event.event_type,
            username=event.username,
            source_ip=event.source_ip,
            service=event.service,
            command=event.command,
            action=event.action,
        )
        for event in evidence
    )

    rule_names = ", ".join(
        detection.name for detection in detections
    )

    if source_ip:
        entity = f"source {source_ip}"
    else:
        entity = correlation_key

    summary = (
        f"{entity} triggered {len(detections)} related "
        f"detection(s): {rule_names}."
    )

    return Incident(
        incident_id=f"INC-{incident_number:04d}",
        severity=highest_severity.severity,
        source_ip=source_ip,
        start_time=start_time,
        end_time=end_time,
        detections=tuple(detections),
        timeline=timeline,
        summary=summary,
    )
