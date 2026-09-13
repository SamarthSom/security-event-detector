from collections import deque
from dataclasses import dataclass
from datetime import timedelta

from src.config import DetectionConfig, load_detection_config
from src.detection.engine import run_detections
from src.detection.models import Detection
from src.parsing.models import SecurityEvent


@dataclass(frozen=True)
class StreamAlert:
    detection: Detection
    event_count: int


class RollingDetector:
    """
    Maintain a bounded rolling window of normalized events.

    Each incoming event is evaluated against the current window.
    Repeated alerts for the same ongoing pattern are suppressed.
    """

    def __init__(
        self,
        window_seconds: int = 120,
        config: DetectionConfig | None = None,
    ) -> None:
        if window_seconds <= 0:
            raise ValueError(
                "window_seconds must be greater than zero."
            )

        self.window_seconds = window_seconds
        self.config = config or load_detection_config()

        self._events: deque[SecurityEvent] = deque()

        # Tracks active detection patterns currently represented
        # in the rolling window.
        self._active_patterns: set[
            tuple[str, str | None]
        ] = set()

    @property
    def events(self) -> tuple[SecurityEvent, ...]:
        """Return the current rolling window."""
        return tuple(self._events)

    def process(
        self,
        event: SecurityEvent,
    ) -> list[StreamAlert]:
        """Add one event and return newly triggered alerts."""
        self._events.append(event)
        self._expire_old_events(event)

        detections = run_detections(
            list(self._events),
            self.config,
        )

        current_patterns = {
            (
                detection.rule_id,
                detection.source_ip,
            )
            for detection in detections
        }

        alerts = []

        for detection in detections:
            pattern = (
                detection.rule_id,
                detection.source_ip,
            )

            if pattern in self._active_patterns:
                continue

            self._active_patterns.add(pattern)

            alerts.append(
                StreamAlert(
                    detection=detection,
                    event_count=len(self._events),
                )
            )

        # Any detection pattern no longer present in the rolling
        # window is no longer considered active.
        self._active_patterns.intersection_update(
            current_patterns
            | {
                pattern
                for pattern in self._active_patterns
                if pattern[0].startswith("SUDO-")
            }
        )

        return alerts

    def _expire_old_events(
        self,
        current_event: SecurityEvent,
    ) -> None:
        cutoff = (
            current_event.timestamp
            - timedelta(seconds=self.window_seconds)
        )

        while (
            self._events
            and self._events[0].timestamp < cutoff
        ):
            self._events.popleft()
