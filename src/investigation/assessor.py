from dataclasses import dataclass

from src.correlation.models import Incident
from src.scoring.engine import calculate_risk


@dataclass(frozen=True)
class InvestigationAssessment:
    finding: str
    confidence: str
    rationale: str
    recommended_actions: tuple[str, ...]


def assess_incident(
    incident: Incident,
) -> InvestigationAssessment:
    """
    Produce a cautious analyst-oriented assessment.

    This function describes what the available evidence supports.
    It does not claim that an attack or compromise has been confirmed.
    """
    risk = calculate_risk(incident)

    rule_ids = {
        detection.rule_id
        for detection in incident.detections
    }

    evidence_count = len(incident.timeline)

    accounts = {
        event.username
        for event in incident.timeline
        if event.username is not None
    }

    if "AUTH-001" in rule_ids and "AUTH-002" in rule_ids:
        finding = (
            "The evidence indicates concentrated authentication "
            "activity involving repeated failures and multiple "
            "targeted accounts."
        )

        rationale = (
            f"The incident contains {evidence_count} supporting "
            f"events and {len(accounts)} distinct account(s), with "
            "multiple authentication detection rules contributing "
            "to the incident."
        )

        actions = (
            "Determine whether the source is an authorized system.",
            "Review successful authentication events associated with the source.",
            "Review the targeted accounts for subsequent unusual activity.",
            "Correlate the incident with additional host or network telemetry.",
        )

    elif "AUTH-001" in rule_ids:
        finding = (
            "The evidence indicates repeated authentication failures "
            "from a single source."
        )

        rationale = (
            f"{evidence_count} supporting event(s) matched the "
            "brute-force detection threshold."
        )

        actions = (
            "Determine whether the source is an authorized system.",
            "Review authentication successes immediately following the failures.",
            "Check whether the targeted account was expected to be accessed.",
        )

    elif "SUDO-001" in rule_ids or "SUDO-002" in rule_ids:
        finding = (
            "The evidence indicates security-sensitive privileged "
            "activity that may warrant administrative review."
        )

        rationale = (
            f"The incident contains {evidence_count} privileged "
            "event(s) associated with security-sensitive actions."
        )

        actions = (
            "Confirm that the privileged activity was authorized.",
            "Review the executed commands and their intended purpose.",
            "Review surrounding authentication and session activity.",
        )

    else:
        finding = (
            "The evidence indicates activity that matched a configured "
            "security detection rule and requires analyst review."
        )

        rationale = (
            f"{evidence_count} supporting event(s) contributed to "
            "the incident."
        )

        actions = (
            "Review the supporting evidence.",
            "Determine whether the activity was authorized.",
            "Correlate the event with additional available telemetry.",
        )

    return InvestigationAssessment(
        finding=finding,
        confidence=risk.confidence,
        rationale=rationale,
        recommended_actions=actions,
    )
