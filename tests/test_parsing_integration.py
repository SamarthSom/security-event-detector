import tempfile
import unittest
from pathlib import Path

from src.parsing.pipeline import parse_file


class TestParsingIntegration(unittest.TestCase):

    def test_synthetic_file_is_normalized(self):
        content = (
            "2026-09-13 10:05:11 "
            "SSH_LOGIN_FAILED "
            "user=admin "
            "src=192.168.1.50\n"
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "sample.log"
            path.write_text(content, encoding="utf-8")

            events = parse_file(str(path))

            self.assertEqual(len(events), 1)
            self.assertEqual(
                events[0].event_type,
                "SSH_LOGIN_FAILED",
            )
            self.assertEqual(
                events[0].source_ip,
                "192.168.1.50",
            )

    def test_ubuntu_file_is_normalized(self):
        content = (
            "2026-09-13T08:47:21.531456+00:00 "
            "MSI sudo: sam : TTY=/dev/pts/0 ; "
            "PWD=/home/sam ; USER=root ; "
            "COMMAND=/usr/bin/systemctl restart ssh\n"
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "auth.log"
            path.write_text(content, encoding="utf-8")

            events = parse_file(str(path))

            self.assertEqual(len(events), 1)
            self.assertEqual(
                events[0].event_type,
                "UBUNTU_SUDO",
            )
            self.assertEqual(events[0].username, "sam")
            self.assertEqual(
                events[0].command,
                "/usr/bin/systemctl restart ssh",
            )

    def test_unknown_format_is_rejected(self):
        content = "this is not a supported log format\n"

        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "unknown.log"
            path.write_text(content, encoding="utf-8")

            with self.assertRaises(ValueError):
                parse_file(str(path))


if __name__ == "__main__":
    unittest.main()
