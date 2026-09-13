import unittest
from datetime import datetime

from src.correlation.engine import correlate_detections
from src.detection.models import Detection
from src.parsing.models import SecurityEvent


class TestCorrelation(unittest.TestCase):

    def make_event(self, seconds, username="admin"):
        timestamp = datetime(
            2026,
            9,
            13,
            10,
            0,
            seconds,
        )

        return SecurityEvent(
            timestamp=timestamp,
            event_type="SSH_LOGIN_FAILED",
            username=username,
            source_ip="10.0.0.45",
            hostname="TEST",
            service="ssh",
            command=None,
            command_name=None,
            action=None,
            target_user=None,
            working_directory=None,
            raw_message="test event",
        )

    def make_detection(self, rule_id, name, seconds):
        event = self.make_event(seconds)

        return Detection(
            rule_id=rule_id,
            name=name,
            severity="HIGH",
            source_ip="10.0.0.45",
            description="Test detection",
            evidence=(event,),
            detected_at=event.timestamp,
        )

    def test_related_detections_are_correlated(self):
        detections = [
            self.make_detection(
                "AUTH-001",
                "SSH Brute-Force Pattern",
                10,
            ),
            self.make_detection(
                "AUTH-002",
                "Multi-Account Authentication Pattern",
                20,
            ),
        ]

        incidents = correlate_detections(detections)

        self.assertEqual(len(incidents), 1)
        self.assertEqual(
            incidents[0].incident_id,
            "INC-0001",
        )
        self.assertEqual(
            len(incidents[0].detections),
            2,
        )
        self.assertEqual(
            len(incidents[0].timeline),
            2,
        )

    def test_separate_time_windows_create_separate_incidents(self):
        detections = [
            self.make_detection(
                "AUTH-001",
                "SSH Brute-Force Pattern",
                10,
            ),
            self.make_detection(
                "AUTH-002",
                "Multi-Account Authentication Pattern",
                50,
            ),
        ]

        incidents = correlate_detections(
            detections,
            window_seconds=20,
        )

        self.assertEqual(len(incidents), 2)


if __name__ == "__main__":
    unittest.main()
