import unittest

from src.cli.main import build_parser


class TestCLI(unittest.TestCase):

    def test_default_window(self):
        parser = build_parser()

        args = parser.parse_args(["auth.log"])

        self.assertEqual(args.log_file, "auth.log")
        self.assertEqual(args.window, 120)

    def test_custom_window(self):
        parser = build_parser()

        args = parser.parse_args(
            ["auth.log", "--window", "300"]
        )

        self.assertEqual(args.window, 300)


if __name__ == "__main__":
    unittest.main()
