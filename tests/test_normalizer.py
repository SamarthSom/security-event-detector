import unittest
from datetime import datetime, timezone

from src.parsing.auth_parser import AuthEvent
from src.parsing.normalizer import (
    classify_command,
    get_command_name,
    normalize_synthetic_event,
    normalize_ubuntu_event,
)
from src.parsing.ubuntu_auth_parser import UbuntuAuthEvent


class TestNormalizer(unittest.TestCase):

    def test_command_name_from_path(self):
        self.assertEqual(
            get_command_name("/usr/bin/systemctl restart ssh"),
            "systemctl",
        )

    def test_command_classification(self):
        self.assertEqual(
            classify_command("/usr/bin/chmod 600 file"),
            "PERMISSION_CHANGE",
        )

        self.assertEqual(
            classify_command(
                "/usr/bin/grep sudo: /var/log/auth.log"
            ),
            "LOG_ANALYSIS",
        )

        self.assertEqual(
            classify_command(
                "/usr/sbin/usermod -aG sudo sam"
            ),
            "ACCOUNT_MANAGEMENT",
        )

    def test_unknown_command(self):
        self.assertEqual(
            classify_command(
                "/usr/local/bin/custom-tool"
            ),
            "OTHER",
        )

    def test_normalize_synthetic_event(self):
        event = AuthEvent(
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
            source_ip="192.168.1.50",
        )

        normalized = normalize_synthetic_event(event)

        self.assertEqual(
            normalized.event_type,
            "SSH_LOGIN_FAILED",
        )

        self.assertEqual(
            normalized.username,
            "admin",
        )

        self.assertEqual(
            normalized.source_ip,
            "192.168.1.50",
        )

        self.assertIsNone(
            normalized.hostname
        )

    def test_normalize_ubuntu_event(self):
        event = UbuntuAuthEvent(
            timestamp=datetime(
                2026,
                9,
                13,
                8,
                47,
                21,
                531456,
                tzinfo=timezone.utc,
            ),
            hostname="MSI",
            service="sudo",
            username="sam",
            command="/usr/bin/systemctl restart ssh",
            target_user="root",
            source_ip=None,
            event_type="UBUNTU_SUDO",
            raw_message=(
                "sam : TTY=/dev/pts/0 ; "
                "PWD=/home/sam ; "
                "USER=root ; "
                "COMMAND=/usr/bin/systemctl restart ssh"
            ),
        )

        normalized = normalize_ubuntu_event(event)

        self.assertEqual(
            normalized.event_type,
            "UBUNTU_SUDO",
        )

        self.assertEqual(
            normalized.username,
            "sam",
        )

        self.assertEqual(
            normalized.hostname,
            "MSI",
        )

        self.assertEqual(
            normalized.service,
            "sudo",
        )

        self.assertEqual(
            normalized.command,
            "/usr/bin/systemctl restart ssh",
        )

        self.assertEqual(
            normalized.command_name,
            "systemctl",
        )

        self.assertEqual(
            normalized.action,
            "SERVICE_MANAGEMENT",
        )

        self.assertEqual(
            normalized.target_user,
            "root",
        )

        self.assertIsNone(
            normalized.source_ip
        )

        self.assertEqual(
            normalized.working_directory,
            "/home/sam",
        )

    def test_normalize_failed_ssh_event(self):
        event = UbuntuAuthEvent(
            timestamp=datetime(
                2026,
                9,
                13,
                10,
                0,
                10,
                tzinfo=timezone.utc,
            ),
            hostname="TEST",
            service="sshd",
            username="admin",
            command=None,
            target_user=None,
            source_ip="10.0.0.45",
            event_type="SSH_LOGIN_FAILED",
            raw_message=(
                "Failed password for admin "
                "from 10.0.0.45 port 22 ssh2"
            ),
        )

        normalized = normalize_ubuntu_event(event)

        self.assertEqual(
            normalized.event_type,
            "SSH_LOGIN_FAILED",
        )

        self.assertEqual(
            normalized.username,
            "admin",
        )

        self.assertEqual(
            normalized.source_ip,
            "10.0.0.45",
        )

        self.assertEqual(
            normalized.service,
            "sshd",
        )


if __name__ == "__main__":
    unittest.main()
