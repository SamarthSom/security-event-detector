import json
from pathlib import Path

from src.correlation.models import Incident
from src.investigation.assessor import assess_incident
from src.scoring.engine import calculate_risk


def _incident_context(incident: Incident) -> dict:
    """Build a serializable investigation context."""
    assessment = calculate_risk(incident)
    investigation = assess_incident(incident)

    accounts = sorted({
        event.username
        for event in incident.timeline
        if event.username is not None
    })

    commands = sorted({
        event.command
        for event in incident.timeline
        if event.command is not None
    })

    actions = sorted({
        event.action
        for event in incident.timeline
        if event.action is not None
    })

    return {
        "incident_id": incident.incident_id,
        "severity": assessment.severity,
        "risk_score": assessment.score,
        "confidence": assessment.confidence,
        "source_ip": incident.source_ip,
        "start_time": incident.start_time.isoformat(),
        "end_time": incident.end_time.isoformat(),
        "summary": incident.summary,
        "finding": investigation.finding,
        "rationale": investigation.rationale,
        "recommended_actions": list(
            investigation.recommended_actions
        ),
        "risk_factors": [
            {
                "name": factor.name,
                "points": factor.points,
                "explanation": factor.explanation,
            }
            for factor in assessment.factors
        ],
        "detections": [
            {
                "rule_id": detection.rule_id,
                "name": detection.name,
                "severity": detection.severity,
                "description": detection.description,
            }
            for detection in incident.detections
        ],
        "accounts": accounts,
        "actions": actions,
        "commands": commands,
        "timeline": [
            {
                "timestamp": event.timestamp.isoformat(),
                "event_type": event.event_type,
                "username": event.username,
                "source_ip": event.source_ip,
                "service": event.service,
                "command": event.command,
                "action": event.action,
            }
            for event in incident.timeline
        ],
    }


def build_report_data(
    incidents: list[Incident],
) -> list[dict]:
    """Convert incidents into report-ready dictionaries."""
    return [
        _incident_context(incident)
        for incident in incidents
    ]


def write_json_report(
    incidents: list[Incident],
    path: str,
) -> None:
    """Write investigation results as JSON."""
    report_data = build_report_data(incidents)

    output_path = Path(path)
    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with output_path.open(
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            report_data,
            file,
            indent=4,
        )


def write_markdown_report(
    incidents: list[Incident],
    path: str,
) -> None:
    """Write investigation results as Markdown."""
    output_path = Path(path)
    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    lines = [
        "# Security Investigation Report",
        "",
        f"**Incidents:** {len(incidents)}",
        "",
    ]

    if not incidents:
        lines.append(
            "No suspicious activity was detected."
        )
    else:
        for incident in incidents:
            context = _incident_context(incident)

            lines.extend([
                f"## {context['incident_id']}",
                "",
                f"**Severity:** `{context['severity']}`",
                "",
                f"**Risk score:** `{context['risk_score']}/100`",
                "",
                f"**Confidence:** `{context['confidence']}`",
                "",
                f"**Source IP:** `{context['source_ip'] or 'N/A'}`",
                "",
                f"**Start:** `{context['start_time']}`",
                "",
                f"**End:** `{context['end_time']}`",
                "",
                "### Finding",
                "",
                context["finding"],
                "",
                "### Rationale",
                "",
                context["rationale"],
                "",
                "### Recommended Investigation",
                "",
            ])

            for action in context["recommended_actions"]:
                lines.append(f"- {action}")

            lines.extend([
                "",
                "### Risk Factors",
                "",
            ])

            if context["risk_factors"]:
                for factor in context["risk_factors"]:
                    lines.append(
                        f"- **+{factor['points']} — "
                        f"{factor['name']}**: "
                        f"{factor['explanation']}"
                    )
            else:
                lines.append(
                    "- No additional risk factors contributed "
                    "to the score."
                )

            lines.extend([
                "",
                "### Detection Rules",
                "",
            ])

            for detection in context["detections"]:
                lines.append(
                    f"- `{detection['rule_id']}` — "
                    f"{detection['name']} "
                    f"({detection['severity']})"
                )

            if context["accounts"]:
                lines.extend([
                    "",
                    "### Accounts",
                    "",
                ])

                for account in context["accounts"]:
                    lines.append(f"- `{account}`")

            if context["actions"]:
                lines.extend([
                    "",
                    "### Actions",
                    "",
                ])

                for action in context["actions"]:
                    lines.append(f"- `{action}`")

            if context["commands"]:
                lines.extend([
                    "",
                    "### Commands",
                    "",
                ])

                for command in context["commands"]:
                    lines.append(f"- `{command}`")

            lines.extend([
                "",
                "### Investigation Timeline",
                "",
            ])

            if context["timeline"]:
                for event in context["timeline"]:
                    details = [
                        f"event=`{event['event_type']}`",
                    ]

                    if event["username"]:
                        details.append(
                            f"user=`{event['username']}`"
                        )

                    if event["source_ip"]:
                        details.append(
                            f"src=`{event['source_ip']}`"
                        )

                    if event["service"]:
                        details.append(
                            f"service=`{event['service']}`"
                        )

                    if event["action"]:
                        details.append(
                            f"action=`{event['action']}`"
                        )

                    if event["command"]:
                        details.append(
                            f"command=`{event['command']}`"
                        )

                    lines.append(
                        f"- `{event['timestamp']}` — "
                        + " — ".join(details)
                    )
            else:
                lines.append(
                    "- No timeline evidence available."
                )

            lines.append("")

    output_path.write_text(
        "\n".join(lines),
        encoding="utf-8",
    )
