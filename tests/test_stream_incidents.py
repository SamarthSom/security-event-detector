import tempfile
import unittest
from datetime import datetime

from src.detection.models import Detection
from src.parsing.models import SecurityEvent
from src.streaming.detector import StreamAlert
from src.streaming.incidents import alert_to_incident
from src.storage.jsonl_store import IncidentStore


class TestStreamIncidents(unittest.TestCase):

    def make_event(self):
        return SecurityEvent(
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

    def make_alert(self):
        event = self.make_event()

        detection = Detection(
            rule_id="AUTH-001",
            name="SSH Brute-Force Pattern",
            severity="HIGH",
            source_ip="10.10.10.25",
            description="Repeated failures",
            evidence=(event,),
            detected_at=event.timestamp,
        )

        return StreamAlert(
            detection=detection,
            event_count=1,
        )

    def test_alert_becomes_incident(self):
        incident = alert_to_incident(
            self.make_alert(),
            1,
        )

        self.assertEqual(
            incident.incident_id,
            "INC-LIVE-0001",
        )

        self.assertEqual(
            incident.source_ip,
            "10.10.10.25",
        )

        self.assertEqual(
            len(incident.detections),
            1,
        )

        self.assertEqual(
            len(incident.timeline),
            1,
        )

    def test_incident_store_persists_and_loads(self):
        incident = alert_to_incident(
            self.make_alert(),
            1,
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            path = f"{temp_dir}/incidents.jsonl"

            store = IncidentStore(path)

            store.save(incident)

            records = store.load_all()

            self.assertEqual(
                len(records),
                1,
            )

            self.assertEqual(
                records[0]["incident_id"],
                "INC-LIVE-0001",
            )

            self.assertEqual(
                records[0]["risk_score"],
                15,
            )


if __name__ == "__main__":
    unittest.main()
