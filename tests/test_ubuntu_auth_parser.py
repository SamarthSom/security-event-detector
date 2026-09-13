import unittest
from datetime import datetime, timezone

from src.parsing.ubuntu_auth_parser import (
    parse_ubuntu_auth_line,
)


class TestUbuntuAuthParser(unittest.TestCase):

    def test_parse_sudo_event(self):
        line = (
            "2026-09-13T08:47:21.531456+00:00 "
            "MSI sudo: sam : TTY=/dev/pts/0 ; "
            "PWD=/home/sam ; USER=root ; "
            "COMMAND=/usr/bin/apt update"
        )

        event = parse_ubuntu_auth_line(line)

        self.assertIsNotNone(event)
        self.assertEqual(
            event.service,
            "sudo",
        )
        self.assertEqual(
            event.username,
            "sam",
        )
        self.assertEqual(
            event.target_user,
            "root",
        )
        self.assertEqual(
            event.command,
            "/usr/bin/apt update",
        )
        self.assertIsNone(
            event.source_ip
        )

    def test_parse_session_event(self):
        line = (
            "2026-09-13T08:46:41.761409+00:00 "
            "MSI systemd-logind[175]: "
            "New session 'c8' of user 'sam' "
            "with class 'user'"
        )

        event = parse_ubuntu_auth_line(line)

        self.assertIsNotNone(event)
        self.assertEqual(
            event.service,
            "systemd-logind",
        )
        self.assertEqual(
            event.username,
            "sam",
        )

    def test_parse_failed_ssh_event(self):
        line = (
            "2026-09-13T10:00:10.000000+00:00 "
            "TEST sshd: Failed password for admin "
            "from 10.0.0.45 port 22 ssh2"
        )

        event = parse_ubuntu_auth_line(line)

        self.assertIsNotNone(event)
        self.assertEqual(
            event.event_type,
            "SSH_LOGIN_FAILED",
        )
        self.assertEqual(
            event.username,
            "admin",
        )
        self.assertEqual(
            event.source_ip,
            "10.0.0.45",
        )

    def test_parse_successful_ssh_event(self):
        line = (
            "2026-09-13T10:00:10.000000+00:00 "
            "TEST sshd: Accepted password for admin "
            "from 10.0.0.45 port 22 ssh2"
        )

        event = parse_ubuntu_auth_line(line)

        self.assertIsNotNone(event)
        self.assertEqual(
            event.event_type,
            "SSH_LOGIN_SUCCESS",
        )
        self.assertEqual(
            event.username,
            "admin",
        )
        self.assertEqual(
            event.source_ip,
            "10.0.0.45",
        )

    def test_invalid_line(self):
        event = parse_ubuntu_auth_line(
            "not a valid auth log entry"
        )

        self.assertIsNone(event)


if __name__ == "__main__":
    unittest.main()
