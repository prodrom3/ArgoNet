# Copyright (c) 2024 prodrom3 / radamic
# Licensed under the MIT License.
# Last updated: 2026-04-02

"""Data classes for ArgoNet results."""

from dataclasses import dataclass, field
from typing import Any


@dataclass
class GeoResult:
    ip: str
    city: str
    country: str
    found: bool = True
    latitude: float | None = None
    longitude: float | None = None
    region: str | None = None
    asn: int | None = None
    asn_org: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "ip": self.ip, "city": self.city,
            "country": self.country, "found": self.found,
        }
        if self.latitude is not None:
            d["latitude"] = self.latitude
        if self.longitude is not None:
            d["longitude"] = self.longitude
        if self.region:
            d["region"] = self.region
        if self.asn is not None:
            d["asn"] = self.asn
        if self.asn_org:
            d["asn_org"] = self.asn_org
        return d


@dataclass
class TracerouteHop:
    ttl: int
    ip: str
    rtt: float | None = None
    hostname: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"ttl": self.ttl, "ip": self.ip, "rtt": self.rtt}
        if self.hostname:
            d["hostname"] = self.hostname
        return d


@dataclass
class TracerouteResult:
    target: str
    success: bool
    hops: list[TracerouteHop] = field(default_factory=list)
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"target": self.target, "success": self.success}
        if self.success:
            d["hops"] = [h.to_dict() for h in self.hops]
        if self.error:
            d["error"] = self.error
        return d


@dataclass
class WhoisResult:
    ip: str
    success: bool
    netname: str | None = None
    org: str | None = None
    cidr: str | None = None
    description: str | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"ip": self.ip, "success": self.success}
        for key in ("netname", "org", "cidr", "description", "error"):
            val = getattr(self, key)
            if val:
                d[key] = val
        return d


@dataclass
class DnsRecords:
    """Extended DNS records for a domain."""
    domain: str
    mx: list[str] = field(default_factory=list)
    txt: list[str] = field(default_factory=list)
    ns: list[str] = field(default_factory=list)
    soa: str | None = None
    cname: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"domain": self.domain}
        if self.mx:
            d["mx"] = self.mx
        if self.txt:
            d["txt"] = self.txt
        if self.ns:
            d["ns"] = self.ns
        if self.soa:
            d["soa"] = self.soa
        if self.cname:
            d["cname"] = self.cname
        return d


@dataclass
class PortResult:
    """Result of a single port scan."""
    port: int
    open: bool
    service: str = ""
    banner: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"port": self.port, "open": self.open, "service": self.service}
        if self.banner:
            d["banner"] = self.banner
        return d


@dataclass
class TlsCertResult:
    """TLS certificate information."""
    host: str
    success: bool
    issuer: str | None = None
    subject: str | None = None
    not_before: str | None = None
    not_after: str | None = None
    sans: list[str] = field(default_factory=list)
    self_signed: bool = False
    protocol: str | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"host": self.host, "success": self.success}
        for key in ("issuer", "subject", "not_before", "not_after", "protocol", "error"):
            val = getattr(self, key)
            if val:
                d[key] = val
        if self.sans:
            d["sans"] = self.sans
        if self.self_signed:
            d["self_signed"] = True
        return d


@dataclass
class AnalysisResult:
    target: str
    is_ip: bool
    resolved_ips: list[str] = field(default_factory=list)
    geo_results: list[GeoResult] = field(default_factory=list)
    traceroute: TracerouteResult | None = None
    whois: WhoisResult | None = None
    dns_records: DnsRecords | None = None
    ports: list[PortResult] = field(default_factory=list)
    tls: TlsCertResult | None = None
    error: str | None = None

    @property
    def has_errors(self) -> bool:
        if self.error:
            return True
        if not self.is_ip and not self.resolved_ips:
            return True
        if self.traceroute and not self.traceroute.success:
            return True
        return False

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"target": self.target, "is_ip": self.is_ip}
        if self.error:
            d["error"] = self.error
        if self.resolved_ips:
            d["resolved_ips"] = self.resolved_ips
        if self.geo_results:
            d["geolocation"] = [g.to_dict() for g in self.geo_results]
        if self.dns_records:
            d["dns_records"] = self.dns_records.to_dict()
        if self.traceroute:
            d["traceroute"] = self.traceroute.to_dict()
        if self.whois:
            d["whois"] = self.whois.to_dict()
        if self.ports:
            d["ports"] = [p.to_dict() for p in self.ports]
        if self.tls:
            d["tls"] = self.tls.to_dict()
        return d
