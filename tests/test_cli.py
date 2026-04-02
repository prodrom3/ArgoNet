"""Tests for core.cli module."""

import io
import os
import unittest
from pathlib import Path
from unittest.mock import patch

from core.cli import VERSION, _find_db_path, _read_stdin_targets, parse_args


class TestParseArgs(unittest.TestCase):
    def test_single_target(self) -> None:
        args = parse_args(["8.8.8.8"])
        self.assertEqual(args.targets, ["8.8.8.8"])

    def test_multiple_targets(self) -> None:
        args = parse_args(["8.8.8.8", "1.1.1.1"])
        self.assertEqual(args.targets, ["8.8.8.8", "1.1.1.1"])

    def test_no_targets_exits(self) -> None:
        with self.assertRaises(SystemExit):
            parse_args([])

    def test_defaults(self) -> None:
        args = parse_args(["8.8.8.8"])
        self.assertFalse(args.no_traceroute)
        self.assertFalse(args.all_ips)
        self.assertFalse(args.json_output)
        self.assertFalse(args.tcp)
        self.assertFalse(args.quiet)
        self.assertFalse(args.whois)
        self.assertEqual(args.max_hops, 20)
        self.assertEqual(args.timeout, 30.0)
        self.assertEqual(args.workers, 4)

    def test_all_flags(self) -> None:
        args = parse_args([
            "--no-traceroute", "--all-ips", "--json", "--tcp",
            "--quiet", "--whois", "--max-hops", "30",
            "--timeout", "10", "--workers", "8",
            "--db", "/path/db.mmdb", "--asn-db", "/path/asn.mmdb",
            "8.8.8.8",
        ])
        self.assertTrue(args.no_traceroute)
        self.assertTrue(args.all_ips)
        self.assertTrue(args.json_output)
        self.assertTrue(args.tcp)
        self.assertTrue(args.quiet)
        self.assertTrue(args.whois)
        self.assertEqual(args.max_hops, 30)
        self.assertEqual(args.timeout, 10.0)
        self.assertEqual(args.workers, 8)
        self.assertEqual(args.db, "/path/db.mmdb")
        self.assertEqual(args.asn_db, "/path/asn.mmdb")

    def test_version_flag(self) -> None:
        with self.assertRaises(SystemExit) as ctx:
            parse_args(["--version"])
        self.assertEqual(ctx.exception.code, 0)


class TestArgValidation(unittest.TestCase):
    def test_workers_zero_rejected(self) -> None:
        with self.assertRaises(SystemExit):
            parse_args(["--workers", "0", "8.8.8.8"])

    def test_workers_negative_rejected(self) -> None:
        with self.assertRaises(SystemExit):
            parse_args(["--workers", "-1", "8.8.8.8"])

    def test_timeout_zero_rejected(self) -> None:
        with self.assertRaises(SystemExit):
            parse_args(["--timeout", "0", "8.8.8.8"])

    def test_timeout_negative_rejected(self) -> None:
        with self.assertRaises(SystemExit):
            parse_args(["--timeout", "-5", "8.8.8.8"])

    def test_max_hops_zero_rejected(self) -> None:
        with self.assertRaises(SystemExit):
            parse_args(["--max-hops", "0", "8.8.8.8"])

    def test_valid_bounds_accepted(self) -> None:
        args = parse_args(["--workers", "1", "--timeout", "0.5", "--max-hops", "1", "8.8.8.8"])
        self.assertEqual(args.workers, 1)
        self.assertEqual(args.timeout, 0.5)
        self.assertEqual(args.max_hops, 1)


class TestStdinTargets(unittest.TestCase):
    def test_reads_piped_input(self) -> None:
        fake_stdin = io.StringIO("8.8.8.8\n1.1.1.1\n")
        with patch("sys.stdin", fake_stdin):
            result = _read_stdin_targets()
        self.assertEqual(result, ["8.8.8.8", "1.1.1.1"])

    def test_skips_comments_and_blank_lines(self) -> None:
        fake_stdin = io.StringIO("# comment\n\n8.8.8.8\n  \n")
        with patch("sys.stdin", fake_stdin):
            result = _read_stdin_targets()
        self.assertEqual(result, ["8.8.8.8"])


class TestFindDbPath(unittest.TestCase):
    def test_cli_value_takes_priority(self) -> None:
        self.assertEqual(_find_db_path("/explicit/path.mmdb"), "/explicit/path.mmdb")

    @patch.dict(os.environ, {"GEOIP_DB_PATH": "/env/path.mmdb"})
    def test_env_var_fallback(self) -> None:
        self.assertEqual(_find_db_path(None), "/env/path.mmdb")

    @patch.dict(os.environ, {}, clear=True)
    @patch("core.cli.Path.home", return_value=Path("/nonexistent_home"))
    def test_none_when_not_found(self, _: unittest.mock.MagicMock) -> None:
        self.assertIsNone(_find_db_path(None))


class TestVersion(unittest.TestCase):
    def test_version_format(self) -> None:
        parts = VERSION.split(".")
        self.assertEqual(len(parts), 3)

    def test_version_matches_file(self) -> None:
        version_file = Path(__file__).resolve().parent.parent / "VERSION"
        self.assertEqual(VERSION, version_file.read_text().strip())


if __name__ == "__main__":
    unittest.main()
