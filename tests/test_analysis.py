import tempfile
import unittest
from pathlib import Path

from src.analysis import analyze_log


class TestAnalysis(unittest.TestCase):

    def test_full_analysis_pipeline(self):
        log_content = """2026-09-13 10:05:11 SSH_LOGIN_FAILED user=admin src=192.168.1.50
2026-09-13 10:05:18 SSH_LOGIN_FAILED user=admin src=192.168.1.50
2026-09-13 10:05:27 SSH_LOGIN_FAILED user=admin src=192.168.1.50
2026-09-13 10:05:35 SSH_LOGIN_FAILED user=admin src=192.168.1.50
2026-09-13 10:05:44 SSH_LOGIN_FAILED user=admin src=192.168.1.50
"""

        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "auth.log"
            path.write_text(log_content, encoding="utf-8")

            result = analyze_log(str(path))

            self.assertEqual(result.events_analyzed, 5)
            self.assertEqual(result.detections_found, 1)
            self.assertEqual(result.incidents_found, 1)

            incident = result.incidents[0]

            self.assertEqual(incident.incident_id, "INC-0001")
            self.assertEqual(incident.severity, "HIGH")
            self.assertEqual(
                incident.source_ip,
                "192.168.1.50",
            )

    def test_normal_activity_creates_no_incident(self):
        log_content = """2026-09-13 10:00:12 SSH_LOGIN_SUCCESS user=sam src=192.168.1.20
2026-09-13 10:01:03 SSH_LOGIN_SUCCESS user=alex src=192.168.1.21
"""

        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "auth.log"
            path.write_text(log_content, encoding="utf-8")

            result = analyze_log(str(path))

            self.assertEqual(result.events_analyzed, 2)
            self.assertEqual(result.detections_found, 0)
            self.assertEqual(result.incidents_found, 0)


if __name__ == "__main__":
    unittest.main()
