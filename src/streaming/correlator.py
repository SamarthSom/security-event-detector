from dataclasses import dataclass, replace
from datetime import timedelta

from src.correlation.engine import correlate_detections
from src.correlation.models import Incident, TimelineEvent
from src.detection.models import Detection


@dataclass(frozen=True)
class CorrelatedStreamIncident:
    incident: Incident
    detection_count: int


class StreamingIncidentCorrelator:
    """
    Maintain recent detections and correlate them into live incidents.

    Exact duplicate detections are ignored. Related detections from
    the same source can be combined within the configured window.
    Evidence is deduplicated before an incident is emitted so that
    overlapping detection rules do not inflate event counts.
    """

    def __init__(
        self,
        window_seconds: int = 120,
    ) -> None:
        if window_seconds <= 0:
            raise ValueError(
                "window_seconds must be greater than zero."
            )

        self.window_seconds = window_seconds
        self._detections: list[Detection] = []
        self._last_signature: tuple | None = None
        self._active_incident_id: str | None = None
        self._incident_number = 1

    @property
    def detections(
        self,
    ) -> tuple[Detection, ...]:
        return tuple(self._detections)

    def process(
        self,
        detection: Detection,
    ) -> CorrelatedStreamIncident | None:
        """Process one detection and return a new or expanded incident."""
        if self._is_duplicate(detection):
            return None

        self._detections.append(detection)

        self._expire_old_detections(
            detection
        )

        incidents = correlate_detections(
            self._detections,
            window_seconds=self.window_seconds,
        )

        if not incidents:
            return None

        incident = self._deduplicate_incident(
            incidents[-1]
        )

        signature = self._incident_signature(
            incident
        )

        if signature == self._last_signature:
            return None

        self._last_signature = signature

        if self._active_incident_id is None:
            self._active_incident_id = (
                f"INC-LIVE-{self._incident_number:04d}"
            )
            self._incident_number += 1

        incident = replace(
            incident,
            incident_id=self._active_incident_id,
        )

        return CorrelatedStreamIncident(
            incident=incident,
            detection_count=len(
                incident.detections
            ),
        )

    def _is_duplicate(
        self,
        detection: Detection,
    ) -> bool:
        signature = self._detection_signature(
            detection
        )

        return any(
            self._detection_signature(existing)
            == signature
            for existing in self._detections
        )

    def _expire_old_detections(
        self,
        current_detection: Detection,
    ) -> None:
        cutoff = (
            current_detection.detected_at
            - timedelta(
                seconds=self.window_seconds
            )
        )

        previous_count = len(
            self._detections
        )

        self._detections = [
            detection
            for detection in self._detections
            if detection.detected_at >= cutoff
        ]

        if len(self._detections) != previous_count:
            if not self._detections:
                self._last_signature = None
                self._active_incident_id = None

    @classmethod
    def _deduplicate_incident(
        cls,
        incident: Incident,
    ) -> Incident:
        """
        Remove overlapping evidence while preserving distinct detections.
        """
        unique_detections: list[Detection] = []
        seen_detection_keys: set[tuple] = set()

        for detection in incident.detections:
            unique_evidence = []
            seen_events: set[tuple] = set()

            for event in detection.evidence:
                event_key = cls._event_signature(
                    event
                )

                if event_key in seen_events:
                    continue

                seen_events.add(event_key)
                unique_evidence.append(event)

            normalized_detection = replace(
                detection,
                evidence=tuple(
                    unique_evidence
                ),
            )

            detection_key = cls._detection_signature(
                normalized_detection
            )

            if detection_key in seen_detection_keys:
                continue

            seen_detection_keys.add(
                detection_key
            )

            unique_detections.append(
                normalized_detection
            )

        unique_events = {}

        for detection in unique_detections:
            for event in detection.evidence:
                unique_events[
                    cls._event_signature(event)
                ] = event

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
            for event in sorted(
                unique_events.values(),
                key=lambda item: item.timestamp,
            )
        )

        return replace(
            incident,
            detections=tuple(
                unique_detections
            ),
            timeline=timeline,
        )

    @staticmethod
    def _event_signature(
        event,
    ) -> tuple:
        return (
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

    @staticmethod
    def _detection_signature(
        detection: Detection,
    ) -> tuple:
        return (
            detection.rule_id,
            detection.source_ip,
            detection.detected_at,
            detection.name,
        )

    @classmethod
    def _incident_signature(
        cls,
        incident: Incident,
    ) -> tuple:
        return tuple(
            cls._detection_signature(
                detection
            )
            for detection in incident.detections
        )
