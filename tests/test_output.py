"""Tests for core.output module (Renderer class)."""

import io
import json
import os
import sys
import unittest
from unittest.mock import patch

from core.models import (
    AnalysisResult,
    GeoResult,
    TracerouteHop,
    TracerouteResult,
    WhoisResult,
)
from core.output import Color, Renderer


class TestColor(unittest.TestCase):
    @patch.dict(os.environ, {"NO_COLOR": "1"})
    def test_no_color_env_disables(self) -> None:
        self.assertFalse(Color.enabled())

    @patch.dict(os.environ, {}, clear=True)
    def test_non_tty_disables(self) -> None:
        original = sys.stdout
        sys.stdout = io.StringIO()
        try:
            self.assertFalse(Color.enabled())
        finally:
            sys.stdout = original

    def test_stringio_stream_disables(self) -> None:
        self.assertFalse(Color.enabled(io.StringIO()))


class TestRendererGeo(unittest.TestCase):
    def test_found_with_asn(self) -> None:
        buf = io.StringIO()
        r = Renderer(out=buf)
        r.geo(GeoResult(ip="8.8.8.8", city="MTV", country="US", asn=15169, asn_org="Google"))
        output = buf.getvalue()
        self.assertIn("AS15169", output)
        self.assertIn("Google", output)

    def test_not_found(self) -> None:
        buf = io.StringIO()
        r = Renderer(out=buf)
        r.geo(GeoResult(ip="10.0.0.1", city="N/A", country="N/A", found=False))
        self.assertIn("N/A", buf.getvalue())


class TestRendererDns(unittest.TestCase):
    def test_with_ips(self) -> None:
        buf = io.StringIO()
        Renderer(out=buf).dns("example.com", ["93.184.216.34"])
        self.assertIn("93.184.216.34", buf.getvalue())

    def test_no_ips(self) -> None:
        buf = io.StringIO()
        Renderer(out=buf).dns("bad.invalid", [])
        self.assertIn("No IPs found", buf.getvalue())


class TestRendererTraceroute(unittest.TestCase):
    def test_success(self) -> None:
        buf = io.StringIO()
        result = TracerouteResult(
            target="8.8.8.8", success=True,
            hops=[TracerouteHop(ttl=1, ip="192.168.1.1", rtt=1.23, hostname="gw")],
        )
        Renderer(out=buf).traceroute(result)
        output = buf.getvalue()
        self.assertIn("192.168.1.1", output)
        self.assertIn("gw", output)

    def test_failure(self) -> None:
        buf = io.StringIO()
        result = TracerouteResult(target="8.8.8.8", success=False, error="denied")
        Renderer(out=buf).traceroute(result)
        self.assertIn("denied", buf.getvalue())


class TestRendererWhois(unittest.TestCase):
    def test_success(self) -> None:
        buf = io.StringIO()
        result = WhoisResult(ip="8.8.8.8", success=True, org="Google LLC", netname="GOGL")
        Renderer(out=buf).whois(result)
        output = buf.getvalue()
        self.assertIn("Google LLC", output)
        self.assertIn("GOGL", output)

    def test_failure(self) -> None:
        buf = io.StringIO()
        result = WhoisResult(ip="8.8.8.8", success=False, error="timed out")
        Renderer(out=buf).whois(result)
        self.assertIn("timed out", buf.getvalue())


class TestRendererProgress(unittest.TestCase):
    def test_shows_progress(self) -> None:
        err = io.StringIO()
        Renderer(err=err).progress(3, 10, "example.com")
        output = err.getvalue()
        self.assertIn("3/10", output)
        self.assertIn("example.com", output)

    def test_quiet_suppresses(self) -> None:
        err = io.StringIO()
        Renderer(err=err, quiet=True).progress(3, 10, "example.com")
        self.assertEqual(err.getvalue(), "")


class TestRendererAnalysis(unittest.TestCase):
    def test_ip_analysis(self) -> None:
        buf = io.StringIO()
        result = AnalysisResult(
            target="8.8.8.8", is_ip=True,
            geo_results=[GeoResult(ip="8.8.8.8", city="MTV", country="US")],
        )
        Renderer(out=buf).analysis(result)
        output = buf.getvalue()
        self.assertIn("MTV", output)
        self.assertNotIn("DNS Resolution", output)

    def test_error(self) -> None:
        buf = io.StringIO()
        result = AnalysisResult(target="bad.invalid", is_ip=False, error="fail")
        Renderer(out=buf).analysis(result)
        self.assertIn("fail", buf.getvalue())

    def test_with_whois(self) -> None:
        buf = io.StringIO()
        result = AnalysisResult(
            target="8.8.8.8", is_ip=True,
            whois=WhoisResult(ip="8.8.8.8", success=True, org="Google"),
        )
        Renderer(out=buf).analysis(result)
        self.assertIn("Google", buf.getvalue())

    def test_db_warning(self) -> None:
        buf = io.StringIO()
        result = AnalysisResult(target="8.8.8.8", is_ip=True)
        Renderer(out=buf).analysis(result, show_db_warning=True)
        self.assertIn("No GeoLite2 database found", buf.getvalue())


class TestRendererJson(unittest.TestCase):
    def test_single_result(self) -> None:
        buf = io.StringIO()
        result = AnalysisResult(target="8.8.8.8", is_ip=True)
        Renderer(out=buf).json_output([result])
        data = json.loads(buf.getvalue())
        self.assertEqual(data["target"], "8.8.8.8")

    def test_multiple_results(self) -> None:
        buf = io.StringIO()
        results = [
            AnalysisResult(target="8.8.8.8", is_ip=True),
            AnalysisResult(target="1.1.1.1", is_ip=True),
        ]
        Renderer(out=buf).json_output(results)
        data = json.loads(buf.getvalue())
        self.assertEqual(len(data["results"]), 2)


if __name__ == "__main__":
    unittest.main()
