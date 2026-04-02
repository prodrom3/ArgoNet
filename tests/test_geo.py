"""Tests for core.geo module."""

import threading
import unittest
from unittest.mock import MagicMock, patch

from core.geo import GeoIPReader, ResultCache
from core.models import GeoResult, TracerouteResult, WhoisResult


class TestGeoIPReader(unittest.TestCase):
    def test_unavailable_when_no_path(self) -> None:
        with GeoIPReader(None) as reader:
            self.assertFalse(reader.available)
            self.assertFalse(reader.asn_available)

    def test_lookup_returns_na_when_unavailable(self) -> None:
        with GeoIPReader(None) as reader:
            result = reader.lookup("8.8.8.8")
            self.assertFalse(result.found)

    @patch("geoip2.database.Reader")
    def test_lookup_with_mocked_reader(self, mock_cls: MagicMock) -> None:
        mock_resp = MagicMock()
        mock_resp.city.name = "Mountain View"
        mock_resp.country.name = "United States"
        mock_resp.location.latitude = 37.386
        mock_resp.location.longitude = -122.084
        mock_resp.subdivisions.most_specific.name = "California"
        mock_reader = MagicMock()
        mock_reader.city.return_value = mock_resp
        mock_cls.return_value = mock_reader

        with GeoIPReader("/fake.mmdb") as reader:
            result = reader.lookup("8.8.8.8")
            self.assertTrue(result.found)
            self.assertEqual(result.city, "Mountain View")

    @patch("geoip2.database.Reader")
    def test_lookup_is_thread_safe(self, mock_cls: MagicMock) -> None:
        mock_resp = MagicMock()
        mock_resp.city.name = "City"
        mock_resp.country.name = "Country"
        mock_resp.location = None
        mock_resp.subdivisions = None
        mock_reader = MagicMock()
        mock_reader.city.return_value = mock_resp
        mock_cls.return_value = mock_reader

        errors: list[str] = []
        with GeoIPReader("/fake.mmdb") as reader:
            def worker(n: int) -> None:
                for _ in range(20):
                    r = reader.lookup("8.8.8.8")
                    if r.city != "City":
                        errors.append(f"Thread {n} got {r.city}")

            threads = [threading.Thread(target=worker, args=(i,)) for i in range(4)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

        self.assertEqual(errors, [])

    @patch("geoip2.database.Reader")
    def test_asn_lookup(self, mock_cls: MagicMock) -> None:
        mock_city_resp = MagicMock()
        mock_city_resp.city.name = "MTV"
        mock_city_resp.country.name = "US"
        mock_city_resp.location = None
        mock_city_resp.subdivisions = None

        mock_asn_resp = MagicMock()
        mock_asn_resp.autonomous_system_number = 15169
        mock_asn_resp.autonomous_system_organization = "Google LLC"

        city_reader = MagicMock()
        city_reader.city.return_value = mock_city_resp
        asn_reader = MagicMock()
        asn_reader.asn.return_value = mock_asn_resp

        mock_cls.side_effect = [city_reader, asn_reader]

        with GeoIPReader("/fake/city.mmdb", asn_db="/fake/asn.mmdb") as reader:
            result = reader.lookup("8.8.8.8")
            self.assertEqual(result.asn, 15169)


class TestResultCache(unittest.TestCase):
    def test_geo_cache(self) -> None:
        cache = ResultCache()
        self.assertIsNone(cache.get_geo("8.8.8.8"))
        cache.set_geo("8.8.8.8", GeoResult(ip="8.8.8.8", city="X", country="Y"))
        self.assertIsNotNone(cache.get_geo("8.8.8.8"))

    def test_whois_cache(self) -> None:
        cache = ResultCache()
        self.assertIsNone(cache.get_whois("8.8.8.8"))
        cache.set_whois("8.8.8.8", WhoisResult(ip="8.8.8.8", success=True))
        self.assertIsNotNone(cache.get_whois("8.8.8.8"))

    def test_bounded_cache_evicts(self) -> None:
        cache = ResultCache(max_size=3)
        for i in range(5):
            cache.set_geo(f"10.0.0.{i}", GeoResult(ip=f"10.0.0.{i}", city="C", country="X"))
        # Oldest entries should have been evicted
        self.assertIsNone(cache.get_geo("10.0.0.0"))
        self.assertIsNone(cache.get_geo("10.0.0.1"))
        self.assertIsNotNone(cache.get_geo("10.0.0.4"))

    def test_thread_safety(self) -> None:
        cache = ResultCache()
        errors: list[str] = []

        def writer(n: int) -> None:
            for i in range(50):
                ip = f"10.0.{n}.{i}"
                cache.set_geo(ip, GeoResult(ip=ip, city=f"C{n}", country="X"))
                result = cache.get_geo(ip)
                if result is None or result.city != f"C{n}":
                    errors.append(f"Mismatch at {ip}")

        threads = [threading.Thread(target=writer, args=(n,)) for n in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])


if __name__ == "__main__":
    unittest.main()
