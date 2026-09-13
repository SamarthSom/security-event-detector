import json
import tempfile
import unittest
from pathlib import Path

from src.config import load_detection_config


class TestDetectionConfig(unittest.TestCase):

    def make_config(self, data):
        temp_dir = tempfile.TemporaryDirectory()
        path = Path(temp_dir.name) / "detections.json"

        path.write_text(
            json.dumps(data),
            encoding="utf-8",
        )

        return temp_dir, path

    def test_load_valid_config(self):
        data = {
            "brute_force": {
                "enabled": True,
                "threshold": 7,
                "window_seconds": 90,
            },
            "password_spray": {
                "enabled": True,
                "account_threshold": 5,
                "window_seconds": 120,
            },
            "sensitive_sudo": {
                "enabled": True,
            },
            "privileged_burst": {
                "enabled": False,
                "threshold": 4,
                "window_seconds": 60,
            },
        }

        temp_dir, path = self.make_config(data)

        try:
            config = load_detection_config(
                str(path)
            )

            self.assertTrue(
                config.brute_force.enabled
            )
            self.assertEqual(
                config.brute_force.threshold,
                7,
            )
            self.assertEqual(
                config.password_spray.account_threshold,
                5,
            )
            self.assertFalse(
                config.privileged_burst.enabled
            )
        finally:
            temp_dir.cleanup()

    def test_missing_file(self):
        with self.assertRaises(FileNotFoundError):
            load_detection_config(
                "/does/not/exist/detections.json"
            )

    def test_invalid_threshold(self):
        data = {
            "brute_force": {
                "enabled": True,
                "threshold": 0,
                "window_seconds": 60,
            },
            "password_spray": {
                "enabled": True,
                "account_threshold": 4,
                "window_seconds": 60,
            },
            "sensitive_sudo": {
                "enabled": True,
            },
            "privileged_burst": {
                "enabled": True,
                "threshold": 3,
                "window_seconds": 60,
            },
        }

        temp_dir, path = self.make_config(data)

        try:
            with self.assertRaises(ValueError):
                load_detection_config(
                    str(path)
                )
        finally:
            temp_dir.cleanup()


if __name__ == "__main__":
    unittest.main()
