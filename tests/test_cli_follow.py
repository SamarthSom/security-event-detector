import unittest

from src.cli.main import build_parser


class TestCLIFollow(unittest.TestCase):

    def test_follow_flag(self):
        parser = build_parser()

        args = parser.parse_args([
            "--follow",
            "data/lab/live_auth.log",
        ])

        self.assertTrue(args.follow)
        self.assertEqual(
            args.log_file,
            "data/lab/live_auth.log",
        )

    def test_follow_without_file(self):
        parser = build_parser()

        args = parser.parse_args([
            "--follow",
        ])

        self.assertTrue(args.follow)
        self.assertIsNone(args.log_file)


if __name__ == "__main__":
    unittest.main()
