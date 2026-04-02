"""Tests for core.tracer module."""

import unittest
from unittest.mock import MagicMock, patch

from core.tracer import _parse_system_output, system_traceroute


class TestParseSystemOutput(unittest.TestCase):
    def test_linux_output(self) -> None:
        output = (
            "traceroute to 8.8.8.8 (8.8.8.8), 20 hops max, 60 byte packets\n"
            " 1  192.168.1.1  1.234 ms  1.123 ms  1.456 ms\n"
            " 2  10.0.0.1  5.678 ms  5.432 ms  5.789 ms\n"
            " 3  * * *\n"
            " 4  8.8.8.8  10.123 ms  10.456 ms  10.789 ms\n"
        )
        hops = _parse_system_output(output)
        self.assertEqual(len(hops), 3)
        self.assertEqual(hops[0].ttl, 1)
        self.assertEqual(hops[0].ip, "192.168.1.1")
        self.assertAlmostEqual(hops[0].rtt or 0, 1.234)

    def test_windows_output(self) -> None:
        output = (
            "Tracing route to 8.8.8.8 over a maximum of 20 hops\n"
            "\n"
            "  1     1 ms     1 ms     1 ms  192.168.1.1\n"
            "  2     5 ms     5 ms     5 ms  10.0.0.1\n"
            "  3     *        *        *     Request timed out.\n"
            "  4    10 ms    10 ms    10 ms  8.8.8.8\n"
        )
        hops = _parse_system_output(output)
        self.assertEqual(len(hops), 3)
        self.assertEqual(hops[0].ttl, 1)
        self.assertEqual(hops[0].ip, "192.168.1.1")

    def test_windows_sub_ms(self) -> None:
        output = (
            "Tracing route to 127.0.0.1\n"
            "  1    <1 ms    <1 ms    <1 ms  127.0.0.1\n"
        )
        hops = _parse_system_output(output)
        self.assertEqual(len(hops), 1)
        self.assertAlmostEqual(hops[0].rtt or 0, 1.0)

    def test_empty_output(self) -> None:
        self.assertEqual(_parse_system_output(""), [])


class TestSystemTraceroute(unittest.TestCase):
    @patch("core.tracer.subprocess.run")
    def test_success(self, mock_run: MagicMock) -> None:
        mock_run.return_value = MagicMock(
            stdout=" 1  192.168.1.1  1.234 ms  1.0 ms  1.0 ms\n",
            stderr="",
        )
        result = system_traceroute("8.8.8.8", max_hops=5, timeout=2.0)
        self.assertTrue(result.success)
        self.assertEqual(len(result.hops), 1)

    @patch("core.tracer.subprocess.run")
    def test_command_not_found(self, mock_run: MagicMock) -> None:
        mock_run.side_effect = FileNotFoundError()
        result = system_traceroute("8.8.8.8")
        self.assertFalse(result.success)
        self.assertIn("not found", result.error or "")

    @patch("core.tracer.subprocess.run")
    def test_timeout(self, mock_run: MagicMock) -> None:
        import subprocess
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="traceroute", timeout=10)
        result = system_traceroute("8.8.8.8")
        self.assertFalse(result.success)
        self.assertIn("timed out", result.error or "")


if __name__ == "__main__":
    unittest.main()
