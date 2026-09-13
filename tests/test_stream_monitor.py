import tempfile
import threading
import time
import unittest
from pathlib import Path

from src.config import (
    BruteForceConfig,
    DetectionConfig,
    PasswordSprayConfig,
    PrivilegedBurstConfig,
    SensitiveSudoConfig,
)
from src.streaming.detector import RollingDetector
from src.streaming.monitor import follow_ubuntu_log


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


class TestStreamMonitor(unittest.TestCase):

    def test_appended_ubuntu_events_are_detected(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "auth.log"

            path.write_text(
                "",
                encoding="utf-8",
            )

            detector = RollingDetector(
                window_seconds=60,
                config=test_config(),
            )

            output = []

            monitor_thread = threading.Thread(
                target=lambda: follow_ubuntu_log(
                    str(path),
                    detector,
                    output_callback=output.append,
                ),
                daemon=True,
            )

            monitor_thread.start()

            time.sleep(0.05)

            base = "2026-09-13T10:00:{:02d}.000000+00:00 TEST sshd: "

            for second in [0, 10, 20, 30, 40]:
                with path.open(
                    "a",
                    encoding="utf-8",
                ) as file:
                    file.write(
                        base.format(second)
                        + "Failed password for admin "
                        + "from 10.0.0.45 port 22 ssh2\n"
                    )

                time.sleep(0.03)

            deadline = time.time() + 1.0

            while not output and time.time() < deadline:
                time.sleep(0.01)

            self.assertTrue(output)

            self.assertTrue(
                any(
                    alert.detection.rule_id == "AUTH-001"
                    for alert in output
                )
            )


    def test_incident_callback_prevents_duplicate_output(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "auth.log"

            path.write_text(
                "",
                encoding="utf-8",
            )

            detector = RollingDetector(
                window_seconds=60,
                config=test_config(),
            )

            incidents = []

            def callback(incident):
                incidents.append(incident)

            thread = threading.Thread(
                target=lambda: follow_ubuntu_log(
                    str(path),
                    detector,
                    incident_callback=callback,
                ),
                daemon=True,
            )

            thread.start()

            time.sleep(0.05)

            base = (
                "2026-09-13T10:00:{:02d}.000000+00:00 "
                "LAB sshd: "
            )

            for second in [0, 10, 20, 30, 40]:
                with path.open(
                    "a",
                    encoding="utf-8",
                ) as file:
                    file.write(
                        base.format(second)
                        + "Failed password for admin "
                        + "from 10.10.10.25 port 22 ssh2\n"
                    )

                time.sleep(0.03)

            deadline = time.time() + 1.0

            while not incidents and time.time() < deadline:
                time.sleep(0.01)

            self.assertEqual(
                len(incidents),
                1,
            )

            self.assertEqual(
                incidents[0].incident_id,
                "INC-LIVE-0001",
            )


if __name__ == "__main__":
    unittest.main()
