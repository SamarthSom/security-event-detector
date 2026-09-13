import tempfile
import unittest
from pathlib import Path

from src.parsing.pipeline import parse_auth_file


class TestAuthPipeline(unittest.TestCase):

    def test_parse_auth_file(self):
        log_content = """2026-09-13 10:05:11 SSH_LOGIN_FAILED user=admin src=192.168.1.50
2026-09-13 10:06:01 SSH_LOGIN_SUCCESS user=sam src=192.168.1.20

invalid log line
"""

        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "auth.log"
            path.write_text(log_content, encoding="utf-8")

            events = parse_auth_file(str(path))

            self.assertEqual(len(events), 2)

            self.assertEqual(events[0].username, "admin")
            self.assertEqual(events[0].event_type, "SSH_LOGIN_FAILED")
            self.assertEqual(events[0].source_ip, "192.168.1.50")

            self.assertEqual(events[1].username, "sam")
            self.assertEqual(events[1].event_type, "SSH_LOGIN_SUCCESS")

    def test_missing_file(self):
        with self.assertRaises(FileNotFoundError):
            parse_auth_file("/does/not/exist.log")


if __name__ == "__main__":
    unittest.main()
