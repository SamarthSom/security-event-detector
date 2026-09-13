import unittest
from datetime import datetime, timedelta

from src.correlation.engine import correlate_detections
from src.detection.models import Detection
from src.parsing.models import SecurityEvent
from src.investigation.assessor import assess_incident


class TestInvestigationAssessment(unittest.TestCase):

    def make_event(self, seconds, username="admin"):
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

    def make_detection(
        self,
        rule_id,
        name,
        events,
        severity="HIGH",
    ):
        return Detection(
            rule_id=rule_id,
            name=name,
            severity=severity,
            source_ip="10.0.0.45",
            description="Test detection",
            evidence=tuple(events),
            detected_at=events[-1].timestamp,
        )

    def test_authentication_incident_gets_cautious_finding(self):
        events = [
            self.make_event(
                i * 5,
                username,
            )
            for i, username in enumerate(
                ["root", "admin", "guest", "backup", "test"]
            )
        ]

        detections = [
            self.make_detection(
                "AUTH-001",
                "SSH Brute-Force Pattern",
                events,
            ),
            self.make_detection(
                "AUTH-002",
                "Multi-Account Authentication Pattern",
                events,
            ),
        ]

        incidents = correlate_detections(detections)

        assessment = assess_incident(incidents[0])

        self.assertIn(
            "authentication",
            assessment.finding.lower(),
        )

        self.assertIn(
            assessment.confidence,
            {"HIGH", "MEDIUM"},
        )

        self.assertGreater(
            len(assessment.recommended_actions),
            1,
        )

    def test_privileged_activity_gets_admin_review_finding(self):
        event = SecurityEvent(
            timestamp=datetime(
                2026,
                9,
                13,
                10,
                0,
                0,
            ),
            event_type="UBUNTU_SUDO",
            username="sam",
            source_ip=None,
            hostname="TEST",
            service="sudo",
            command="/usr/bin/chmod 600 file",
            command_name="chmod",
            action="PERMISSION_CHANGE",
            target_user="root",
            working_directory="/home/sam",
            raw_message="test sudo event",
        )

        detection = Detection(
            rule_id="SUDO-001",
            name="Sensitive Privileged Execution",
            severity="MEDIUM",
            source_ip=None,
            description="Security-sensitive privileged action",
            evidence=(event,),
            detected_at=event.timestamp,
        )

        incidents = correlate_detections([detection])

        assessment = assess_incident(incidents[0])

        self.assertIn(
            "privileged",
            assessment.finding.lower(),
        )

        self.assertIn(
            "authorized",
            " ".join(
                assessment.recommended_actions
            ).lower(),
        )


if __name__ == "__main__":
    unittest.main()
