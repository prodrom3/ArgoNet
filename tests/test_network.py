"""Tests for core.network module."""

import socket
import unittest
from unittest.mock import MagicMock, patch

from core.models import WhoisResult
from core.network import (
    _is_allowed_whois_server,
    _sanitize_whois_query,
    _whois_timestamps,
    resolve_domain,
    reverse_dns,
    validate_ip,
    whois_lookup,
)


class TestValidateIp(unittest.TestCase):
    def test_valid_ipv4(self) -> None:
        self.assertTrue(validate_ip("8.8.8.8"))

    def test_valid_ipv6(self) -> None:
        self.assertTrue(validate_ip("::1"))

    def test_invalid(self) -> None:
        self.assertFalse(validate_ip("not-an-ip"))
        self.assertFalse(validate_ip(""))


class TestResolveDomain(unittest.TestCase):
    @patch("core.network.socket.getaddrinfo")
    def test_successful(self, mock_gai: MagicMock) -> None:
        mock_gai.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0)),
        ]
        self.assertEqual(resolve_domain("example.com"), ["93.184.216.34"])

    @patch("core.network.socket.getaddrinfo")
    def test_failed(self, mock_gai: MagicMock) -> None:
        mock_gai.side_effect = socket.gaierror("fail")
        self.assertEqual(resolve_domain("bad.invalid"), [])


class TestReverseDns(unittest.TestCase):
    @patch("core.network.socket.gethostbyaddr")
    def test_success(self, mock_rdns: MagicMock) -> None:
        mock_rdns.return_value = ("dns.google", [], ["8.8.8.8"])
        self.assertEqual(reverse_dns("8.8.8.8"), "dns.google")

    @patch("core.network.socket.gethostbyaddr")
    def test_failure(self, mock_rdns: MagicMock) -> None:
        mock_rdns.side_effect = socket.herror("not found")
        self.assertIsNone(reverse_dns("10.0.0.1"))


class TestSanitizeWhoisQuery(unittest.TestCase):
    def test_strips_newlines(self) -> None:
        self.assertEqual(_sanitize_whois_query("8.8.8.8\r\nextra"), "8.8.8.8extra")

    def test_strips_control_chars(self) -> None:
        self.assertEqual(_sanitize_whois_query("8.8\x00.8.8"), "8.8.8.8")

    def test_clean_input_unchanged(self) -> None:
        self.assertEqual(_sanitize_whois_query("n 8.8.8.8"), "n 8.8.8.8")


class TestAllowedWhoisServer(unittest.TestCase):
    def test_known_servers_allowed(self) -> None:
        self.assertTrue(_is_allowed_whois_server("whois.arin.net"))
        self.assertTrue(_is_allowed_whois_server("WHOIS.APNIC.NET"))

    def test_unknown_servers_rejected(self) -> None:
        self.assertFalse(_is_allowed_whois_server("evil.example.com"))


class TestWhoisLookup(unittest.TestCase):
    def setUp(self) -> None:
        _whois_timestamps.clear()

    @patch("core.network._whois_query")
    def test_successful_lookup(self, mock_query: MagicMock) -> None:
        mock_query.return_value = "NetName: GOGL\nOrgName: Google LLC\n"
        result = whois_lookup("8.8.8.8")
        self.assertTrue(result.success)
        self.assertEqual(result.org, "Google LLC")

    @patch("core.network._whois_query")
    def test_referral_to_unknown_server_blocked(self, mock_query: MagicMock) -> None:
        mock_query.return_value = "ReferralServer: whois://evil.example.com\nNetName: ARIN\n"
        result = whois_lookup("1.2.3.4")
        mock_query.assert_called_once()
        self.assertEqual(result.netname, "ARIN")

    @patch("core.network._whois_query")
    def test_timeout(self, mock_query: MagicMock) -> None:
        mock_query.side_effect = TimeoutError("timed out")
        result = whois_lookup("8.8.8.8")
        self.assertFalse(result.success)

    def test_rate_limit(self) -> None:
        from core.network import _WHOIS_MAX_QUERIES
        with patch("core.network._whois_query") as mock_query:
            mock_query.return_value = "NetName: TEST\n"
            for _ in range(_WHOIS_MAX_QUERIES):
                whois_lookup("8.8.8.8")
            result = whois_lookup("8.8.8.8")
            self.assertFalse(result.success)
            self.assertIn("rate limit", result.error or "")


if __name__ == "__main__":
    unittest.main()
