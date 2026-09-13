import argparse
import sys

from src.analysis import analyze_log
from src.config import load_detection_config
from src.correlation.models import Incident
from src.investigation.assessor import assess_incident
from src.reporting.renderer import (
    write_json_report,
    write_markdown_report,
)
from src.scoring.engine import calculate_risk
from src.storage.jsonl_store import IncidentStore
from src.streaming.detector import RollingDetector
from src.streaming.monitor import follow_ubuntu_log


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="security-event-detector",
        description=(
            "Analyze authentication logs for suspicious "
            "security activity."
        ),
    )

    parser.add_argument(
        "log_file",
        nargs="?",
        help="Path to an authorized authentication log file.",
    )

    parser.add_argument(
        "--follow",
        action="store_true",
        help="Continuously monitor a growing Ubuntu auth log.",
    )

    parser.add_argument(
        "--window",
        type=int,
        default=120,
        help="Detection window in seconds.",
    )

    parser.add_argument(
        "--report-dir",
        default="reports",
        help="Directory for generated reports.",
    )

    return parser


def _print_live_incident(
    incident: Incident,
) -> None:
    """Print a complete live investigation incident."""
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
    print("Recommended investigation:")

    for action in (
        investigation.recommended_actions
    ):
        print(
            f"  - {action}"
        )

    print()
    print("Detection rules:")

    for detection in incident.detections:
        print(
            f"  - {detection.rule_id}: "
            f"{detection.name}"
        )

    print()
    print("=========================")
    print()


def run_follow_mode(
    args: argparse.Namespace,
) -> int:
    if not args.log_file:
        print(
            "Error: --follow requires a log file.",
            file=sys.stderr,
        )
        return 1

    try:
        config = load_detection_config()

        detector = RollingDetector(
            window_seconds=args.window,
            config=config,
        )

        store = IncidentStore(
            f"{args.report_dir}/live_incidents.jsonl"
        )

        print(
            "=== Security Event Detector ==="
        )
        print()
        print(
            f"Following: {args.log_file}"
        )
        print(
            f"Rolling window: "
            f"{args.window} seconds"
        )
        print(
            f"Incident store: "
            f"{store.path}"
        )
        print(
            "Press Ctrl+C to stop."
        )
        print()

        def handle_incident(
            incident: Incident,
        ) -> None:
            store.save(incident)
            _print_live_incident(incident)

        follow_ubuntu_log(
            args.log_file,
            detector,
            incident_callback=handle_incident,
        )

    except (
        FileNotFoundError,
        ValueError,
    ) as error:
        print(
            f"Error: {error}",
            file=sys.stderr,
        )
        return 1

    except KeyboardInterrupt:
        print()
        print("Monitoring stopped.")

    return 0


def run_batch_mode(
    args: argparse.Namespace,
) -> int:
    if not args.log_file:
        print(
            "Error: a log file is required.",
            file=sys.stderr,
        )
        return 1

    try:
        result = analyze_log(
            args.log_file,
            correlation_window_seconds=args.window,
        )
    except (
        FileNotFoundError,
        ValueError,
    ) as error:
        print(
            f"Error: {error}",
            file=sys.stderr,
        )
        return 1

    json_path = (
        f"{args.report_dir}/security_report.json"
    )

    markdown_path = (
        f"{args.report_dir}/security_report.md"
    )

    write_json_report(
        list(result.incidents),
        json_path,
    )

    write_markdown_report(
        list(result.incidents),
        markdown_path,
    )

    print(
        "=== Security Event Detector ==="
    )
    print()

    print(
        f"Log file: "
        f"{result.log_file}"
    )

    print(
        f"Events analyzed: "
        f"{result.events_analyzed}"
    )

    print(
        f"Detections found: "
        f"{result.detections_found}"
    )

    print(
        f"Incidents found: "
        f"{result.incidents_found}"
    )

    print()

    if not result.incidents:
        print(
            "No suspicious activity detected."
        )
        print()

        print(
            f"JSON report: "
            f"{json_path}"
        )

        print(
            f"Markdown report: "
            f"{markdown_path}"
        )

        return 0

    for incident in result.incidents:
        risk = calculate_risk(incident)
        investigation = assess_incident(
            incident
        )

        print(
            f"[{risk.severity}] "
            f"{incident.incident_id} "
            f"Risk={risk.score}/100 "
            f"Confidence={risk.confidence}"
        )

        print(
            f"Source IP: "
            f"{incident.source_ip or 'N/A'}"
        )

        print(
            f"Start: "
            f"{incident.start_time}"
        )

        print(
            f"End:   "
            f"{incident.end_time}"
        )

        print(
            f"Summary: "
            f"{incident.summary}"
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
        print("Risk factors:")

        if risk.factors:
            for factor in risk.factors:
                print(
                    f"  +{factor.points} "
                    f"{factor.name}"
                )
        else:
            print("  None")

        print()
        print(
            "Recommended investigation:"
        )

        for action in (
            investigation.recommended_actions
        ):
            print(
                f"  - {action}"
            )

        print()
        print("Detection rules:")

        for detection in incident.detections:
            print(
                f"  - {detection.rule_id}: "
                f"{detection.name}"
            )

        print()

    print(
        f"JSON report: "
        f"{json_path}"
    )

    print(
        f"Markdown report: "
        f"{markdown_path}"
    )

    return 0


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.follow:
        return run_follow_mode(args)

    return run_batch_mode(args)


if __name__ == "__main__":
    raise SystemExit(main())
