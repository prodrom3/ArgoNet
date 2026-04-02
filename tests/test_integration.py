"""Optional integration tests that hit real network services.

Run with: python -m pytest tests/test_integration.py -v
These tests are skipped by default in CI. Set ARGONET_INTEGRATION=1 to enable.
"""

import os
import unittest

_INTEGRATION = os.environ.get("ARGONET_INTEGRATION", "0") == "1"
_skip_reason = "Set ARGONET_INTEGRATION=1 to run network integration tests"


@unittest.skipUnless(_INTEGRATION, _skip_reason)
class TestRealDns(unittest.TestCase):
    def test_resolve_google(self) -> None:
        from core.network import resolve_domain
        ips = resolve_domain("dns.google", timeout=10.0)
        self.assertGreater(len(ips), 0)
        self.assertIn("8.8.8.8", ips)

    def test_resolve_nonexistent(self) -> None:
        from core.network import resolve_domain
        ips = resolve_domain("this-domain-does-not-exist.invalid", timeout=5.0)
        self.assertEqual(ips, [])


@unittest.skipUnless(_INTEGRATION, _skip_reason)
class TestRealReverseDns(unittest.TestCase):
    def test_reverse_dns_google(self) -> None:
        from core.network import reverse_dns
        hostname = reverse_dns("8.8.8.8")
        self.assertIsNotNone(hostname)
        self.assertIn("google", hostname or "")


@unittest.skipUnless(_INTEGRATION, _skip_reason)
class TestRealWhois(unittest.TestCase):
    def test_whois_google_dns(self) -> None:
        from core.network import whois_lookup
        result = whois_lookup("8.8.8.8", timeout=15.0)
        self.assertTrue(result.success)
        self.assertIsNotNone(result.org)


@unittest.skipUnless(_INTEGRATION, _skip_reason)
class TestRealAnalysis(unittest.TestCase):
    def test_full_analysis_no_traceroute(self) -> None:
        from core.geo import GeoIPReader
        from core.network import analyze_target
        with GeoIPReader(None) as reader:
            result = analyze_target(
                "8.8.8.8", reader, no_traceroute=True, timeout=10.0,
            )
        self.assertTrue(result.is_ip)
        self.assertEqual(result.resolved_ips, ["8.8.8.8"])
        self.assertFalse(result.has_errors)


if __name__ == "__main__":
    unittest.main()
