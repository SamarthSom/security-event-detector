import unittest
from datetime import datetime

from src.parsing.auth_parser import parse_auth_line


class TestAuthParser(unittest.TestCase):

    def test_valid_line(self):
        line = (
            "2026-09-13 10:05:11 "
            "SSH_LOGIN_FAILED "
            "user=admin "
            "src=192.168.1.50"
        )

        event = parse_auth_line(line)

        self.assertIsNotNone(event)
        self.assertEqual(
            event.timestamp,
            datetime(2026, 9, 13, 10, 5, 11),
        )
        self.assertEqual(event.event_type, "SSH_LOGIN_FAILED")
        self.assertEqual(event.username, "admin")
        self.assertEqual(event.source_ip, "192.168.1.50")

    def test_invalid_line(self):
        event = parse_auth_line("this is not a valid log")

        self.assertIsNone(event)

    def test_empty_line(self):
        event = parse_auth_line("")

        self.assertIsNone(event)


if __name__ == "__main__":
    unittest.main()
