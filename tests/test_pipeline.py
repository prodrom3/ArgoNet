"""Tests for core.pipeline module."""

import asyncio
import unittest
from unittest.mock import MagicMock, patch

from core.geo import GeoIPReader, ResultCache
from core.models import GeoResult, TracerouteResult, WhoisResult
from core.pipeline import PipelineConfig, analyze_target


class TestAnalyzeTarget(unittest.TestCase):
    def _run(self, coro: object) -> object:
        return asyncio.run(coro)  # type: ignore[arg-type]

    def test_ip_target_without_db(self) -> None:
        with GeoIPReader(None) as reader:
            result = self._run(analyze_target(
                "8.8.8.8", reader,
                PipelineConfig(no_traceroute=True),
            ))
        self.assertTrue(result.is_ip)
        self.assertIsNone(result.traceroute)

    @patch("core.pipeline.resolve_domain", return_value=[])
    def test_dns_failure(self, _: MagicMock) -> None:
        with GeoIPReader(None) as reader:
            result = self._run(analyze_target(
                "bad.invalid", reader,
                PipelineConfig(no_traceroute=True),
            ))
        self.assertTrue(result.has_errors)

    def test_cache_used_for_geo(self) -> None:
        cache = ResultCache()
        cache.set_geo("8.8.8.8", GeoResult(ip="8.8.8.8", city="Cached", country="X"))
        mock_reader = MagicMock(spec=GeoIPReader)
        mock_reader.available = True
        mock_reader.asn_available = False
        mock_reader.lookup.side_effect = RuntimeError("should not be called")

        result = self._run(analyze_target(
            "8.8.8.8", mock_reader,
            PipelineConfig(no_traceroute=True), cache,
        ))
        self.assertEqual(result.geo_results[0].city, "Cached")

    def test_cache_used_for_traceroute(self) -> None:
        cache = ResultCache()
        cached_tr = TracerouteResult(target="8.8.8.8", success=True, hops=[])
        cache.set_trace("8.8.8.8", cached_tr)

        with GeoIPReader(None) as reader:
            result = self._run(analyze_target(
                "8.8.8.8", reader, PipelineConfig(), cache,
            ))
        self.assertIs(result.traceroute, cached_tr)

    def test_cache_used_for_whois(self) -> None:
        cache = ResultCache()
        cached_wr = WhoisResult(ip="8.8.8.8", success=True, org="Cached")
        cache.set_whois("8.8.8.8", cached_wr)

        with GeoIPReader(None) as reader:
            result = self._run(analyze_target(
                "8.8.8.8", reader,
                PipelineConfig(no_traceroute=True, do_whois=True), cache,
            ))
        self.assertIs(result.whois, cached_wr)

    @patch("core.pipeline.whois_lookup")
    def test_whois_enabled(self, mock_whois: MagicMock) -> None:
        mock_whois.return_value = WhoisResult(ip="8.8.8.8", success=True, org="G")
        with GeoIPReader(None) as reader:
            result = self._run(analyze_target(
                "8.8.8.8", reader,
                PipelineConfig(no_traceroute=True, do_whois=True),
            ))
        self.assertIsNotNone(result.whois)


class TestPipelineConfig(unittest.TestCase):
    def test_defaults(self) -> None:
        cfg = PipelineConfig()
        self.assertEqual(cfg.max_hops, 20)
        self.assertEqual(cfg.timeout, 30.0)
        self.assertFalse(cfg.no_traceroute)
        self.assertFalse(cfg.use_scapy)
        self.assertFalse(cfg.use_tcp)
        self.assertFalse(cfg.do_whois)


if __name__ == "__main__":
    unittest.main()
