from src.correlation.models import Incident
from src.scoring.models import RiskAssessment, RiskFactor


def calculate_risk(
    incident: Incident,
) -> RiskAssessment:
    """Calculate explainable risk and confidence for an incident."""
    score = 0
    factors = []

    detection_ids = {
        detection.rule_id
        for detection in incident.detections
    }

    evidence_map = {}

    for detection in incident.detections:
        for event in detection.evidence:
            key = (
                event.timestamp,
                event.event_type,
                event.username,
                event.source_ip,
                event.hostname,
                event.service,
                event.command,
                event.action,
                event.target_user,
                event.working_directory,
                event.raw_message,
            )

            evidence_map[key] = event

    evidence = list(evidence_map.values())

    usernames = {
        event.username
        for event in evidence
        if event.username is not None
    }

    if len(detection_ids) >= 2:
        factors.append(
            RiskFactor(
                name="Multiple detection rules",
                points=20,
                explanation=(
                    f"{len(detection_ids)} distinct detection rules "
                    "contributed to the incident."
                ),
            )
        )
        score += 20

    if len(evidence) >= 10:
        factors.append(
            RiskFactor(
                name="High event volume",
                points=20,
                explanation=(
                    f"{len(evidence)} supporting events were "
                    "associated with the incident."
                ),
            )
        )
        score += 20

    elif len(evidence) >= 5:
        factors.append(
            RiskFactor(
                name="Elevated event volume",
                points=10,
                explanation=(
                    f"{len(evidence)} supporting events were "
                    "associated with the incident."
                ),
            )
        )
        score += 10

    duration = (
        incident.end_time - incident.start_time
    ).total_seconds()

    if duration <= 60 and len(evidence) >= 5:
        factors.append(
            RiskFactor(
                name="Compressed activity window",
                points=15,
                explanation=(
                    f"The observed activity occurred within "
                    f"{duration:.0f} seconds."
                ),
            )
        )
        score += 15

    if len(usernames) >= 4:
        factors.append(
            RiskFactor(
                name="Multiple accounts involved",
                points=20,
                explanation=(
                    f"{len(usernames)} distinct accounts appeared "
                    "in the supporting evidence."
                ),
            )
        )
        score += 20

    if any(
        detection.severity == "CRITICAL"
        for detection in incident.detections
    ):
        factors.append(
            RiskFactor(
                name="Critical detection",
                points=25,
                explanation=(
                    "At least one contributing rule is critical."
                ),
            )
        )
        score += 25

    elif any(
        detection.severity == "HIGH"
        for detection in incident.detections
    ):
        factors.append(
            RiskFactor(
                name="High-severity detection",
                points=15,
                explanation=(
                    "At least one contributing rule is high severity."
                ),
            )
        )
        score += 15

    score = min(score, 100)

    if len(detection_ids) >= 2 and len(evidence) >= 5:
        confidence = "HIGH"
    elif len(evidence) >= 3:
        confidence = "MEDIUM"
    else:
        confidence = "LOW"

    if score >= 75:
        severity = "CRITICAL"
    elif score >= 50:
        severity = "HIGH"
    elif score >= 25:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    return RiskAssessment(
        score=score,
        severity=severity,
        confidence=confidence,
        factors=tuple(factors),
    )
