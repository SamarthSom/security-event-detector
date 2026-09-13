import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src.ingestion.follower import follow_file


class TestFileFollower(unittest.TestCase):

    def test_reads_existing_lines(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "sample.log"

            path.write_text(
                "first\n\nsecond\n",
                encoding="utf-8",
            )

            follower = follow_file(
                str(path),
                poll_interval=0,
            )

            self.assertEqual(
                next(follower),
                "first",
            )

            self.assertEqual(
                next(follower),
                "second",
            )

    def test_missing_file(self):
        with self.assertRaises(FileNotFoundError):
            next(
                follow_file(
                    "/does/not/exist.log",
                    poll_interval=0,
                )
            )

    def test_directory_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            with self.assertRaises(ValueError):
                next(
                    follow_file(
                        temp_dir,
                        poll_interval=0,
                    )
                )

    def test_waits_for_new_line(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "sample.log"

            path.write_text(
                "first\n",
                encoding="utf-8",
            )

            follower = follow_file(
                str(path),
                poll_interval=0.01,
            )

            self.assertEqual(
                next(follower),
                "first",
            )

            def add_line(_):
                with path.open(
                    "a",
                    encoding="utf-8",
                ) as file:
                    file.write("second\n")

            with patch(
                "src.ingestion.follower.time.sleep",
                side_effect=add_line,
            ):
                self.assertEqual(
                    next(follower),
                    "second",
                )

    def test_skips_blank_lines(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "sample.log"

            path.write_text(
                "\nfirst\n\nsecond\n",
                encoding="utf-8",
            )

            follower = follow_file(
                str(path),
                poll_interval=0,
            )

            self.assertEqual(
                next(follower),
                "first",
            )

            self.assertEqual(
                next(follower),
                "second",
            )


if __name__ == "__main__":
    unittest.main()
