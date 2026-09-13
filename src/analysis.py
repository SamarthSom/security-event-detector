from dataclasses import dataclass
from pathlib import Path

from src.correlation.engine import correlate_detections
from src.correlation.models import Incident
from src.detection.engine import run_detections
from src.parsing.pipeline import parse_file


@dataclass(frozen=True)
class AnalysisResult:
    log_file: str
    events_analyzed: int
    detections_found: int
    incidents_found: int
    incidents: tuple[Incident, ...]


def analyze_log(
    log_file: str,
    correlation_window_seconds: int = 120,
) -> AnalysisResult:
    """Run the complete detection pipeline against a supported log file."""
    events = parse_file(log_file)
    detections = run_detections(events)

    incidents = correlate_detections(
        detections,
        window_seconds=correlation_window_seconds,
    )

    return AnalysisResult(
        log_file=str(Path(log_file)),
        events_analyzed=len(events),
        detections_found=len(detections),
        incidents_found=len(incidents),
        incidents=tuple(incidents),
    )
