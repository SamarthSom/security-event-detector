import tempfile
import unittest
from pathlib import Path

from src.ingestion.reader import read_log_file


class TestLogReader(unittest.TestCase):

    def test_reads_non_empty_lines(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "sample.log"
            path.write_text(
                "first line\n\nsecond line\n",
                encoding="utf-8",
            )

            result = read_log_file(str(path))

            self.assertEqual(result, ["first line", "second line"])

    def test_missing_file(self):
        with self.assertRaises(FileNotFoundError):
            read_log_file("/does/not/exist.log")


if __name__ == "__main__":
    unittest.main()
