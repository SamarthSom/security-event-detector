import unittest
from datetime import datetime, timedelta

from src.correlation.models import Incident, TimelineEvent
from src.detection.models import Detection
from src.parsing.models import SecurityEvent
from src.scoring.engine import calculate_risk


class TestRiskScoring(unittest.TestCase):

    def make_event(
        self,
        seconds,
        username,
        source_ip="10.0.0.45",
    ):
        return SecurityEvent(
            timestamp=datetime(
                2026,
                9,
                13,
                10,
                0,
                seconds,
            ),
            event_type="SSH_LOGIN_FAILED",
            username=username,
            source_ip=source_ip,
            hostname="TEST",
            service="ssh",
            command=None,
            command_name=None,
            action=None,
            target_user=None,
            working_directory=None,
            raw_message="test",
        )

    def make_detection(
        self,
        rule_id,
        name,
        evidence,
        severity="HIGH",
    ):
        return Detection(
            rule_id=rule_id,
            name=name,
            severity=severity,
            source_ip="10.0.0.45",
            description="Test detection",
            evidence=tuple(evidence),
            detected_at=evidence[-1].timestamp,
        )

    def make_incident(self, detections):
        evidence = [
            event
            for detection in detections
            for event in detection.evidence
        ]

        evidence.sort(
            key=lambda event: event.timestamp
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
            incident_id="INC-TEST",
            severity="HIGH",
            source_ip="10.0.0.45",
            start_time=evidence[0].timestamp,
            end_time=evidence[-1].timestamp,
            detections=tuple(detections),
            timeline=timeline,
            summary="Test incident",
        )

    def test_high_risk_incident(self):
        events = [
            self.make_event(
                i * 5,
                f"user{i}",
            )
            for i in range(10)
        ]

        detections = [
            self.make_detection(
                "AUTH-001",
                "Brute Force",
                events,
            ),
            self.make_detection(
                "AUTH-002",
                "Password Spray",
                events,
            ),
        ]

        assessment = calculate_risk(
            self.make_incident(detections)
        )

        self.assertGreaterEqual(
            assessment.score,
            60,
        )

        self.assertIn(
            assessment.severity,
            {"HIGH", "CRITICAL"},
        )

        self.assertIn(
            assessment.confidence,
            {"HIGH", "MEDIUM"},
        )

    def test_low_risk_incident(self):
        event = self.make_event(0, "sam")

        detection = self.make_detection(
            "SUDO-001",
            "Sensitive Privileged Execution",
            [event],
            severity="MEDIUM",
        )

        assessment = calculate_risk(
            self.make_incident([detection])
        )

        self.assertEqual(
            assessment.score,
            0,
        )

        self.assertEqual(
            assessment.severity,
            "LOW",
        )

        self.assertEqual(
            assessment.confidence,
            "LOW",
        )

        self.assertEqual(
            assessment.factors,
            (),
        )


if __name__ == "__main__":
    unittest.main()


class TestUniqueEvidenceScoring(unittest.TestCase):

    def test_overlapping_evidence_is_counted_once(self):
        from datetime import datetime, timezone

        from src.correlation.models import Incident
        from src.detection.models import Detection
        from src.parsing.models import SecurityEvent

        timestamp = datetime(
            2026,
            9,
            13,
            10,
            0,
            0,
            tzinfo=timezone.utc,
        )

        events = tuple(
            SecurityEvent(
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
                raw_message=f"event-{i}",
            )
            for i in range(8)
        )

        detection_one = Detection(
            rule_id="AUTH-001",
            name="SSH Brute-Force Pattern",
            severity="HIGH",
            source_ip="10.10.10.25",
            description="test",
            evidence=events[:5],
            detected_at=timestamp,
        )

        detection_two = Detection(
            rule_id="AUTH-002",
            name="Multi-Account Authentication Pattern",
            severity="HIGH",
            source_ip="10.10.10.25",
            description="test",
            evidence=events,
            detected_at=timestamp,
        )

        incident = Incident(
            incident_id="INC-TEST-UNIQUE",
            severity="HIGH",
            source_ip="10.10.10.25",
            start_time=timestamp,
            end_time=timestamp,
            detections=(
                detection_one,
                detection_two,
            ),
            timeline=(),
            summary="test",
        )

        assessment = calculate_risk(
            incident
        )

        self.assertTrue(
            any(
                factor.name == "Elevated event volume"
                for factor in assessment.factors
            )
        )

        self.assertFalse(
            any(
                factor.name == "High event volume"
                for factor in assessment.factors
            )
        )
