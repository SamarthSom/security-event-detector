import unittest
from datetime import datetime, timedelta

from src.config import (
    BruteForceConfig,
    DetectionConfig,
    PasswordSprayConfig,
    PrivilegedBurstConfig,
    SensitiveSudoConfig,
)
from src.parsing.models import SecurityEvent
from src.streaming.detector import RollingDetector


def test_config() -> DetectionConfig:
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


class TestRollingDetector(unittest.TestCase):

    def make_event(
        self,
        seconds: int,
        event_type: str = "SSH_LOGIN_FAILED",
        username: str = "admin",
        source_ip: str = "10.0.0.45",
    ) -> SecurityEvent:
        return SecurityEvent(
            timestamp=datetime(
                2026,
                9,
                13,
                10,
                0,
                seconds,
            ),
            event_type=event_type,
            username=username,
            source_ip=source_ip,
            hostname="TEST",
            service="ssh",
            command=None,
            command_name=None,
            action=None,
            target_user=None,
            working_directory=None,
            raw_message="test",
        )

    def test_detects_brute_force_as_events_arrive(self):
        detector = RollingDetector(
            window_seconds=60,
            config=test_config(),
        )

        all_alerts = []

        for seconds in [0, 10, 20, 30, 40]:
            alerts = detector.process(
                self.make_event(seconds)
            )
            all_alerts.extend(alerts)

        rule_ids = {
            alert.detection.rule_id
            for alert in all_alerts
        }

        self.assertIn(
            "AUTH-001",
            rule_ids,
        )

    def test_does_not_repeat_same_detection(self):
        detector = RollingDetector(
            window_seconds=60,
            config=test_config(),
        )

        alerts = []

        for seconds in [0, 10, 20, 30, 40, 50]:
            alerts.extend(
                detector.process(
                    self.make_event(seconds)
                )
            )

        brute_force_alerts = [
            alert
            for alert in alerts
            if alert.detection.rule_id == "AUTH-001"
        ]

        self.assertEqual(
            len(brute_force_alerts),
            1,
        )

    def test_old_events_expire(self):
        detector = RollingDetector(
            window_seconds=30,
            config=test_config(),
        )

        for seconds in [0, 10, 20]:
            detector.process(
                self.make_event(seconds)
            )

        self.assertEqual(
            len(detector.events),
            3,
        )

        detector.process(
            self.make_event(40)
        )

        event_timestamps = [
            event.timestamp.second
            for event in detector.events
        ]

        self.assertNotIn(
            0,
            event_timestamps,
        )

    def test_normal_activity_produces_no_alert(self):
        detector = RollingDetector(
            window_seconds=60,
            config=test_config(),
        )

        alerts = []

        for seconds in [0, 10, 20]:
            alerts.extend(
                detector.process(
                    self.make_event(
                        seconds,
                        event_type="SSH_LOGIN_SUCCESS",
                    )
                )
            )

        self.assertEqual(
            alerts,
            [],
        )

    def test_invalid_window_is_rejected(self):
        with self.assertRaises(ValueError):
            RollingDetector(
                window_seconds=0,
                config=test_config(),
            )


if __name__ == "__main__":
    unittest.main()
