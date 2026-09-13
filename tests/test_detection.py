import unittest
from datetime import datetime, timedelta, timezone

from src.config import (
    DetectionConfig,
    BruteForceConfig,
    PasswordSprayConfig,
    SensitiveSudoConfig,
    PrivilegedBurstConfig,
)
from src.detection.engine import run_detections
from src.parsing.models import SecurityEvent


def default_config():
    return DetectionConfig(
        brute_force=BruteForceConfig(
            enabled=True,
            threshold=5,
            window_seconds=60,
        ),
        password_spray=PasswordSprayConfig(
            enabled=True,
            account_threshold=4,
            window_seconds=60,
        ),
        sensitive_sudo=SensitiveSudoConfig(
            enabled=True,
        ),
        privileged_burst=PrivilegedBurstConfig(
            enabled=True,
            threshold=3,
            window_seconds=60,
        ),
    )


class TestDetectionEngine(unittest.TestCase):

    def make_event(
        self,
        timestamp,
        event_type,
        username=None,
        source_ip=None,
        command=None,
        command_name=None,
        action=None,
        target_user=None,
        working_directory=None,
    ):
        return SecurityEvent(
            timestamp=timestamp,
            event_type=event_type,
            username=username,
            source_ip=source_ip,
            hostname="TEST",
            service="test",
            command=command,
            command_name=command_name,
            action=action,
            target_user=target_user,
            working_directory=working_directory,
            raw_message="test event",
        )

    def test_brute_force(self):
        base = datetime(
            2026,
            9,
            13,
            10,
            0,
            0,
        )

        events = [
            self.make_event(
                base + timedelta(seconds=i * 10),
                "SSH_LOGIN_FAILED",
                username="admin",
                source_ip="192.168.1.50",
            )
            for i in range(5)
        ]

        detections = run_detections(
            events,
            default_config(),
        )

        rule_ids = {
            detection.rule_id
            for detection in detections
        }

        self.assertIn(
            "AUTH-001",
            rule_ids,
        )

    def test_password_spray(self):
        base = datetime(
            2026,
            9,
            13,
            10,
            0,
            0,
        )

        users = [
            "root",
            "admin",
            "guest",
            "backup",
        ]

        events = [
            self.make_event(
                base + timedelta(seconds=i * 10),
                "SSH_LOGIN_FAILED",
                username=user,
                source_ip="10.0.0.45",
            )
            for i, user in enumerate(users)
        ]

        detections = run_detections(
            events,
            default_config(),
        )

        rule_ids = {
            detection.rule_id
            for detection in detections
        }

        self.assertIn(
            "AUTH-002",
            rule_ids,
        )

    def test_normal_login(self):
        event = self.make_event(
            datetime(
                2026,
                9,
                13,
                10,
                0,
                0,
            ),
            "SSH_LOGIN_SUCCESS",
            username="sam",
            source_ip="192.168.1.20",
        )

        detections = run_detections(
            [event],
            default_config(),
        )

        self.assertEqual(
            detections,
            [],
        )

    def test_failed_attempts_below_threshold(self):
        base = datetime(
            2026,
            9,
            13,
            10,
            0,
            0,
        )

        events = [
            self.make_event(
                base + timedelta(seconds=i * 10),
                "SSH_LOGIN_FAILED",
                username="admin",
                source_ip="192.168.1.50",
            )
            for i in range(4)
        ]

        detections = run_detections(
            events,
            default_config(),
        )

        self.assertEqual(
            detections,
            [],
        )

    def test_sensitive_sudo_command(self):
        event = self.make_event(
            datetime(
                2026,
                9,
                13,
                10,
                0,
                0,
                tzinfo=timezone.utc,
            ),
            "UBUNTU_SUDO",
            username="sam",
            command="/usr/bin/systemctl restart ssh",
            command_name="systemctl",
            action="SERVICE_MANAGEMENT",
            target_user="root",
            working_directory="/home/sam",
        )

        detections = run_detections(
            [event],
            default_config(),
        )

        rule_ids = {
            detection.rule_id
            for detection in detections
        }

        self.assertIn(
            "SUDO-001",
            rule_ids,
        )

    def test_disabled_brute_force_rule(self):
        config = default_config()

        config = DetectionConfig(
            brute_force=BruteForceConfig(
                enabled=False,
                threshold=5,
                window_seconds=60,
            ),
            password_spray=config.password_spray,
            sensitive_sudo=config.sensitive_sudo,
            privileged_burst=config.privileged_burst,
        )

        base = datetime(
            2026,
            9,
            13,
            10,
            0,
            0,
        )

        events = [
            self.make_event(
                base + timedelta(seconds=i * 10),
                "SSH_LOGIN_FAILED",
                username="admin",
                source_ip="192.168.1.50",
            )
            for i in range(5)
        ]

        detections = run_detections(
            events,
            config,
        )

        rule_ids = {
            detection.rule_id
            for detection in detections
        }

        self.assertNotIn(
            "AUTH-001",
            rule_ids,
        )


if __name__ == "__main__":
    unittest.main()
