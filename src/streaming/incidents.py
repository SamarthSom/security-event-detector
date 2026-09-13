from src.correlation.models import Incident, TimelineEvent
from src.streaming.detector import StreamAlert


def alert_to_incident(
    alert: StreamAlert,
    incident_number: int,
) -> Incident:
    """Convert a live detection alert into an investigation incident."""
    detection = alert.detection

    evidence = sorted(
        detection.evidence,
        key=lambda event: event.timestamp,
    )

    if not evidence:
        raise ValueError(
            "Cannot create an incident without evidence."
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

    return Incident(
        incident_id=f"INC-LIVE-{incident_number:04d}",
        severity=detection.severity,
        source_ip=detection.source_ip,
        start_time=evidence[0].timestamp,
        end_time=evidence[-1].timestamp,
        detections=(detection,),
        timeline=timeline,
        summary=(
            f"Live detection {detection.rule_id} identified "
            f"{detection.name}."
        ),
    )
