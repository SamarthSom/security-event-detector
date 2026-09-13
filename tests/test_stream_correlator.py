import unittest
from datetime import datetime, timezone

from src.detection.models import Detection
from src.parsing.models import SecurityEvent
from src.streaming.correlator import (
    StreamingIncidentCorrelator,
)


class TestStreamingIncidentCorrelator(unittest.TestCase):

    def make_detection(
        self,
        seconds: int,
        rule_id: str,
        name: str,
    ) -> Detection:
        timestamp = datetime(
            2026,
            9,
            13,
            10,
            0,
            seconds,
            tzinfo=timezone.utc,
        )

        event = SecurityEvent(
            timestamp=timestamp,
            event_type="SSH_LOGIN_FAILED",
            username="admin",
            source_ip="10.10.10.25",
            hostname="LAB",
            service="sshd",
            command=None,
            command_name=None,
            action=None,
            target_user=None,
            working_directory=None,
            raw_message="test",
        )

        return Detection(
            rule_id=rule_id,
            name=name,
            severity="HIGH",
            source_ip="10.10.10.25",
            description="test detection",
            evidence=(event,),
            detected_at=timestamp,
        )

    def test_first_detection_creates_incident(self):
        correlator = StreamingIncidentCorrelator(
            window_seconds=120,
        )

        detection = self.make_detection(
            0,
            "AUTH-001",
            "SSH Brute-Force Pattern",
        )

        result = correlator.process(
            detection
        )

        self.assertIsNotNone(result)

        assert result is not None

        self.assertEqual(
            result.detection_count,
            1,
        )

        self.assertEqual(
            result.incident.source_ip,
            "10.10.10.25",
        )

    def test_related_detection_expands_incident(self):
        correlator = StreamingIncidentCorrelator(
            window_seconds=120,
        )

        first = self.make_detection(
            0,
            "AUTH-001",
            "SSH Brute-Force Pattern",
        )

        second = self.make_detection(
            20,
            "AUTH-002",
            "Multi-Account Authentication Pattern",
        )

        first_result = correlator.process(
            first
        )

        second_result = correlator.process(
            second
        )

        self.assertIsNotNone(
            first_result
        )

        self.assertIsNotNone(
            second_result
        )

        assert second_result is not None

        rule_ids = {
            detection.rule_id
            for detection in (
                second_result.incident.detections
            )
        }

        self.assertEqual(
            rule_ids,
            {
                "AUTH-001",
                "AUTH-002",
            },
        )

        self.assertEqual(
            second_result.detection_count,
            2,
        )

    def test_duplicate_state_does_not_emit_again(self):
        correlator = StreamingIncidentCorrelator(
            window_seconds=120,
        )

        detection = self.make_detection(
            0,
            "AUTH-001",
            "SSH Brute-Force Pattern",
        )

        first = correlator.process(
            detection
        )

        second = correlator.process(
            detection
        )

        self.assertIsNotNone(first)
        self.assertIsNone(second)

    def test_old_detection_expires(self):
        correlator = StreamingIncidentCorrelator(
            window_seconds=30,
        )

        first = self.make_detection(
            0,
            "AUTH-001",
            "SSH Brute-Force Pattern",
        )

        second = self.make_detection(
            40,
            "AUTH-002",
            "Multi-Account Authentication Pattern",
        )

        correlator.process(first)

        result = correlator.process(
            second
        )

        self.assertIsNotNone(result)

        assert result is not None

        rule_ids = {
            detection.rule_id
            for detection in (
                result.incident.detections
            )
        }

        self.assertEqual(
            rule_ids,
            {"AUTH-002"},
        )


    def test_overlapping_evidence_is_deduplicated(self):
        correlator = StreamingIncidentCorrelator(
            window_seconds=120,
        )

        first = self.make_detection(
            0,
            "AUTH-001",
            "SSH Brute-Force Pattern",
        )

        second = self.make_detection(
            20,
            "AUTH-002",
            "Multi-Account Authentication Pattern",
        )

        first_result = correlator.process(first)
        second_result = correlator.process(second)

        self.assertIsNotNone(first_result)
        self.assertIsNotNone(second_result)

        assert second_result is not None

        timeline = second_result.incident.timeline

        self.assertEqual(
            len(timeline),
            2,
        )

        timestamps = [
            event.timestamp
            for event in timeline
        ]

        self.assertEqual(
            timestamps,
            sorted(set(timestamps)),
        )

        total_evidence = sum(
            len(detection.evidence)
            for detection in (
                second_result.incident.detections
            )
        )

        self.assertEqual(
            total_evidence,
            2,
        )


if __name__ == "__main__":
    unittest.main()


    def test_related_detections_keep_same_incident_id(self):
        correlator = StreamingIncidentCorrelator(
            window_seconds=120,
        )

        first = self.make_detection(
            0,
            "AUTH-001",
            "SSH Brute-Force Pattern",
        )

        second = self.make_detection(
            20,
            "AUTH-002",
            "Multi-Account Authentication Pattern",
        )

        first_result = correlator.process(
            first
        )

        second_result = correlator.process(
            second
        )

        self.assertIsNotNone(
            first_result
        )
        self.assertIsNotNone(
            second_result
        )

        assert first_result is not None
        assert second_result is not None

        self.assertEqual(
            first_result.incident.incident_id,
            second_result.incident.incident_id,
        )

        self.assertEqual(
            second_result.detection_count,
            2,
        )
