import unittest
from unittest.mock import patch

from main import build_arg_parser


class TestCLI(unittest.TestCase):

    def setUp(self):
        self.parser = build_arg_parser()

    def test_default_arguments(self):
        self.assertEqual(self.parser.prog, "sentrix")
        args = self.parser.parse_args(["example.com"])
        self.assertEqual(args.targets, ["example.com"])
        self.assertEqual(args.ports, "top-200")
        self.assertFalse(args.no_ping)
        self.assertFalse(args.verbose)
        self.assertEqual(args.format, "json,html")

    def test_complex_flags(self):
        cmd = [
            "example.com",
            "-p", "1-1000",
            "--no-ping",
            "--nvd-key", "test_nvd_key_abc",
            "--circl-key", "test_circl_key_xyz",
            "--shodan-key", "test_shodan_key_123",
            "-o", "report.html",
            "-v",
            "--format", "html,markdown",
            "--threads", "20",
        ]
        args = self.parser.parse_args(cmd)
        self.assertEqual(args.targets, ["example.com"])
        self.assertEqual(args.ports, "1-1000")
        self.assertTrue(args.no_ping)
        self.assertEqual(args.nvd_key, "test_nvd_key_abc")
        self.assertEqual(args.circl_key, "test_circl_key_xyz")
        self.assertEqual(args.shodan_key, "test_shodan_key_123")
        self.assertEqual(args.output_file, "report.html")
        self.assertTrue(args.verbose)
        self.assertEqual(args.format, "html,markdown")
        self.assertEqual(args.threads, 20)

    def test_input_file_flag(self):
        args = self.parser.parse_args(["-iL", "targets.txt"])
        self.assertEqual(args.input_file, "targets.txt")
        self.assertEqual(args.targets, [])

    @patch("builtins.input", return_value="192.168.1.1, example.com")
    def test_interactive_mode_parsing(self, mock_input):
        import re
        user_input = mock_input()
        tokens = [t.strip() for t in re.split(r"[\s,;]+", user_input) if t.strip()]
        self.assertEqual(tokens, ["192.168.1.1", "example.com"])


if __name__ == "__main__":
    unittest.main()

