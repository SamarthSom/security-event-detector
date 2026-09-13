import tempfile
import unittest
from datetime import datetime

from src.correlation.models import Incident, TimelineEvent
from src.detection.models import Detection
from src.parsing.models import SecurityEvent
from src.reporting.renderer import (
    build_report_data,
    write_json_report,
    write_markdown_report,
)


class TestReporting(unittest.TestCase):

    def make_incident(self):
        event = SecurityEvent(
            timestamp=datetime(
                2026,
                9,
                13,
                10,
                0,
                0,
            ),
            event_type="SSH_LOGIN_FAILED",
            username="admin",
            source_ip="10.0.0.45",
            hostname="TEST",
            service="ssh",
            command=None,
            command_name=None,
            action=None,
            target_user=None,
            working_directory=None,
            raw_message="test",
        )

        detection = Detection(
            rule_id="AUTH-001",
            name="SSH Brute-Force Pattern",
            severity="HIGH",
            source_ip="10.0.0.45",
            description="Repeated failures",
            evidence=(event,),
            detected_at=event.timestamp,
        )

        timeline_event = TimelineEvent(
            timestamp=event.timestamp,
            event_type=event.event_type,
            username=event.username,
            source_ip=event.source_ip,
            service=event.service,
            command=event.command,
            action=event.action,
        )

        return Incident(
            incident_id="INC-TEST",
            severity="HIGH",
            source_ip="10.0.0.45",
            start_time=event.timestamp,
            end_time=event.timestamp,
            detections=(detection,),
            timeline=(timeline_event,),
            summary="Test incident",
        )

    def test_build_report_data(self):
        data = build_report_data(
            [self.make_incident()]
        )

        self.assertEqual(len(data), 1)
        self.assertEqual(
            data[0]["incident_id"],
            "INC-TEST",
        )
        self.assertEqual(
            data[0]["source_ip"],
            "10.0.0.45",
        )
        self.assertEqual(
            data[0]["detections"][0]["rule_id"],
            "AUTH-001",
        )
        self.assertIn(
            "finding",
            data[0],
        )
        self.assertIn(
            "rationale",
            data[0],
        )
        self.assertIn(
            "recommended_actions",
            data[0],
        )
        self.assertIn(
            "confidence",
            data[0],
        )
        self.assertEqual(
            len(data[0]["timeline"]),
            1,
        )

    def test_write_json_report(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = f"{temp_dir}/report.json"

            write_json_report(
                [self.make_incident()],
                path,
            )

            with open(
                path,
                "r",
                encoding="utf-8",
            ) as file:
                content = file.read()

            self.assertIn("INC-TEST", content)
            self.assertIn("AUTH-001", content)
            self.assertIn("recommended_actions", content)

    def test_write_markdown_report(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = f"{temp_dir}/report.md"

            write_markdown_report(
                [self.make_incident()],
                path,
            )

            with open(
                path,
                "r",
                encoding="utf-8",
            ) as file:
                content = file.read()

            self.assertIn(
                "# Security Investigation Report",
                content,
            )
            self.assertIn("INC-TEST", content)
            self.assertIn(
                "SSH Brute-Force Pattern",
                content,
            )
            self.assertIn(
                "Confidence",
                content,
            )
            self.assertIn(
                "Investigation Timeline",
                content,
            )
            self.assertIn(
                "Recommended Investigation",
                content,
            )


if __name__ == "__main__":
    unittest.main()
