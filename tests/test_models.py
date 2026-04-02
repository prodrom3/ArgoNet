"""Tests for core.models module."""

import unittest

from core.models import (
    AnalysisResult,
    GeoResult,
    TracerouteHop,
    TracerouteResult,
    WhoisResult,
)


class TestGeoResult(unittest.TestCase):
    def test_defaults(self) -> None:
        result = GeoResult(ip="1.1.1.1", city="Sydney", country="Australia")
        self.assertTrue(result.found)
        self.assertIsNone(result.latitude)
        self.assertIsNone(result.region)
        self.assertIsNone(result.asn)

    def test_to_dict_basic(self) -> None:
        result = GeoResult(ip="8.8.8.8", city="MTV", country="US")
        d = result.to_dict()
        self.assertNotIn("latitude", d)
        self.assertNotIn("asn", d)

    def test_to_dict_with_asn(self) -> None:
        result = GeoResult(
            ip="8.8.8.8", city="MTV", country="US",
            asn=15169, asn_org="Google LLC",
        )
        d = result.to_dict()
        self.assertEqual(d["asn"], 15169)
        self.assertEqual(d["asn_org"], "Google LLC")

    def test_to_dict_with_geo_coords(self) -> None:
        result = GeoResult(
            ip="8.8.8.8", city="MTV", country="US",
            latitude=37.386, longitude=-122.084, region="CA",
        )
        d = result.to_dict()
        self.assertEqual(d["latitude"], 37.386)
        self.assertEqual(d["region"], "CA")


class TestTracerouteHop(unittest.TestCase):
    def test_with_hostname(self) -> None:
        hop = TracerouteHop(ttl=1, ip="192.168.1.1", rtt=1.23, hostname="gw.local")
        d = hop.to_dict()
        self.assertEqual(d["hostname"], "gw.local")

    def test_without_hostname(self) -> None:
        hop = TracerouteHop(ttl=5, ip="10.0.0.1")
        d = hop.to_dict()
        self.assertNotIn("hostname", d)


class TestTracerouteResult(unittest.TestCase):
    def test_to_dict_success(self) -> None:
        result = TracerouteResult(
            target="8.8.8.8", success=True,
            hops=[TracerouteHop(ttl=1, ip="10.0.0.1", rtt=1.0)],
        )
        d = result.to_dict()
        self.assertTrue(d["success"])
        self.assertEqual(len(d["hops"]), 1)

    def test_to_dict_failure(self) -> None:
        result = TracerouteResult(target="8.8.8.8", success=False, error="denied")
        d = result.to_dict()
        self.assertNotIn("hops", d)
        self.assertEqual(d["error"], "denied")


class TestWhoisResult(unittest.TestCase):
    def test_success(self) -> None:
        result = WhoisResult(
            ip="8.8.8.8", success=True,
            org="Google LLC", netname="GOGL", cidr="8.8.8.0/24",
        )
        d = result.to_dict()
        self.assertTrue(d["success"])
        self.assertEqual(d["org"], "Google LLC")
        self.assertEqual(d["netname"], "GOGL")
        self.assertEqual(d["cidr"], "8.8.8.0/24")

    def test_failure(self) -> None:
        result = WhoisResult(ip="8.8.8.8", success=False, error="timed out")
        d = result.to_dict()
        self.assertFalse(d["success"])
        self.assertEqual(d["error"], "timed out")

    def test_partial(self) -> None:
        result = WhoisResult(ip="8.8.8.8", success=True, org="Google LLC")
        d = result.to_dict()
        self.assertNotIn("netname", d)
        self.assertNotIn("cidr", d)


class TestAnalysisResult(unittest.TestCase):
    def test_has_errors_on_dns_failure(self) -> None:
        result = AnalysisResult(target="bad.invalid", is_ip=False, error="fail")
        self.assertTrue(result.has_errors)

    def test_no_errors_on_success(self) -> None:
        result = AnalysisResult(
            target="8.8.8.8", is_ip=True, resolved_ips=["8.8.8.8"],
            geo_results=[GeoResult(ip="8.8.8.8", city="MTV", country="US")],
        )
        self.assertFalse(result.has_errors)

    def test_to_dict_with_whois(self) -> None:
        result = AnalysisResult(
            target="8.8.8.8", is_ip=True,
            whois=WhoisResult(ip="8.8.8.8", success=True, org="Google LLC"),
        )
        d = result.to_dict()
        self.assertIn("whois", d)
        self.assertEqual(d["whois"]["org"], "Google LLC")


if __name__ == "__main__":
    unittest.main()
