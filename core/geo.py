# Copyright (c) 2024 prodrom3 / radamic
# Licensed under the MIT License.
# Last updated: 2026-04-02

"""GeoIP reader (city + ASN) and result caching."""

import threading
from typing import Any

from core.models import GeoResult, TracerouteResult, WhoisResult

# Maximum entries per cache type to prevent unbounded memory growth
_MAX_CACHE_SIZE = 10_000


class GeoIPReader:
    """Context manager wrapping the GeoLite2 city and ASN database readers."""

    def __init__(self, city_db: str | None, asn_db: str | None = None) -> None:
        self._city_db = city_db
        self._asn_db = asn_db
        self._city_reader: Any = None
        self._asn_reader: Any = None
        self._available = False
        self._asn_available = False
        self._not_found_error: type[Exception] | None = None
        self._lock = threading.Lock()

    def __enter__(self) -> GeoIPReader:
        try:
            from geoip2 import database
            from geoip2.errors import AddressNotFoundError
            self._not_found_error = AddressNotFoundError
        except ImportError:
            return self

        if self._city_db:
            try:
                self._city_reader = database.Reader(self._city_db)
                self._available = True
            except FileNotFoundError:
                pass

        if self._asn_db:
            try:
                self._asn_reader = database.Reader(self._asn_db)
                self._asn_available = True
            except FileNotFoundError:
                pass

        return self

    def __exit__(self, *args: object) -> None:
        if self._city_reader is not None:
            self._city_reader.close()
        if self._asn_reader is not None:
            self._asn_reader.close()

    @property
    def available(self) -> bool:
        return self._available

    @property
    def asn_available(self) -> bool:
        return self._asn_available

    def lookup(self, ip: str) -> GeoResult:
        with self._lock:
            return self._lookup_unlocked(ip)

    def _lookup_unlocked(self, ip: str) -> GeoResult:
        if not self._available or self._city_reader is None:
            if self._asn_available:
                return self._asn_only_lookup(ip)
            return GeoResult(ip=ip, city="N/A", country="N/A", found=False)

        try:
            response = self._city_reader.city(ip)
            city = response.city.name or "Unknown"
            country = response.country.name or "Unknown"
            location = response.location
            subdivisions = response.subdivisions

            asn_num = None
            asn_org = None
            if self._asn_available and self._asn_reader is not None:
                try:
                    asn_resp = self._asn_reader.asn(ip)
                    asn_num = asn_resp.autonomous_system_number
                    asn_org = asn_resp.autonomous_system_organization
                except Exception:
                    pass

            return GeoResult(
                ip=ip,
                city=city,
                country=country,
                latitude=location.latitude if location else None,
                longitude=location.longitude if location else None,
                region=subdivisions.most_specific.name if subdivisions else None,
                asn=asn_num,
                asn_org=asn_org,
            )
        except Exception as exc:
            if self._not_found_error and isinstance(exc, self._not_found_error):
                return GeoResult(ip=ip, city="Not Found", country="Not Found", found=False)
            return GeoResult(ip=ip, city="Error", country="Error", found=False)

    def _asn_only_lookup(self, ip: str) -> GeoResult:
        """Look up ASN info only (when no city db is available)."""
        if self._asn_reader is None:
            return GeoResult(ip=ip, city="N/A", country="N/A", found=False)
        try:
            asn_resp = self._asn_reader.asn(ip)
            return GeoResult(
                ip=ip,
                city="N/A",
                country="N/A",
                found=False,
                asn=asn_resp.autonomous_system_number,
                asn_org=asn_resp.autonomous_system_organization,
            )
        except Exception:
            return GeoResult(ip=ip, city="N/A", country="N/A", found=False)


class ResultCache:
    """Thread-safe, bounded cache for geolocation, traceroute, and WHOIS results."""

    def __init__(self, max_size: int = _MAX_CACHE_SIZE) -> None:
        self._geo: dict[str, GeoResult] = {}
        self._trace: dict[str, TracerouteResult] = {}
        self._whois: dict[str, WhoisResult] = {}
        self._lock = threading.Lock()
        self._max_size = max_size

    def _evict_if_full(self, d: dict[str, Any]) -> None:
        """Remove the oldest entry if the cache is at capacity."""
        if len(d) >= self._max_size:
            oldest_key = next(iter(d))
            del d[oldest_key]

    def get_geo(self, ip: str) -> GeoResult | None:
        with self._lock:
            return self._geo.get(ip)

    def set_geo(self, ip: str, result: GeoResult) -> None:
        with self._lock:
            self._evict_if_full(self._geo)
            self._geo[ip] = result

    def get_trace(self, ip: str) -> TracerouteResult | None:
        with self._lock:
            return self._trace.get(ip)

    def set_trace(self, ip: str, result: TracerouteResult) -> None:
        with self._lock:
            self._evict_if_full(self._trace)
            self._trace[ip] = result

    def get_whois(self, ip: str) -> WhoisResult | None:
        with self._lock:
            return self._whois.get(ip)

    def set_whois(self, ip: str, result: WhoisResult) -> None:
        with self._lock:
            self._evict_if_full(self._whois)
            self._whois[ip] = result
