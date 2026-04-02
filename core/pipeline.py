# Copyright (c) 2024 prodrom3 / radamic
# Licensed under the MIT License.
# Last updated: 2026-04-02

"""Analysis pipeline: runs probes (DNS, geo, traceroute, WHOIS, ports, TLS) on a target."""

import argparse
import asyncio
import logging
from dataclasses import dataclass, field

from core.dns import query_dns_records
from core.geo import GeoIPReader, ResultCache
from core.models import (
    AnalysisResult,
    DnsRecords,
    GeoResult,
    PortResult,
    TlsCertResult,
    TracerouteResult,
    WhoisResult,
)
from core.network import resolve_domain, validate_ip, whois_lookup
from core.scanner import scan_ports, tls_cert_info
from core.tracer import perform_traceroute

logger = logging.getLogger("argonet")


@dataclass
class PipelineConfig:
    max_hops: int = 20
    timeout: float = 30.0
    no_traceroute: bool = False
    all_ips: bool = False
    use_scapy: bool = False
    use_tcp: bool = False
    do_whois: bool = False
    dns_all: bool = False
    do_ports: bool = False
    port_list: list[int] | None = None
    do_tls: bool = False

    @classmethod
    def from_args(cls, args: argparse.Namespace) -> PipelineConfig:
        return cls(
            max_hops=args.max_hops,
            timeout=args.timeout,
            no_traceroute=args.no_traceroute,
            all_ips=args.all_ips,
            use_scapy=args.scapy,
            use_tcp=args.tcp,
            do_whois=args.whois,
            dns_all=args.dns_all,
            do_ports=args.ports is not None,
            port_list=args.port_list,
            do_tls=args.tls,
        )


async def analyze_target(
    target: str,
    geo_reader: GeoIPReader,
    config: PipelineConfig,
    cache: ResultCache | None = None,
) -> AnalysisResult:
    is_ip = validate_ip(target)
    result = AnalysisResult(target=target, is_ip=is_ip)

    # Phase 1: DNS resolution
    if is_ip:
        trace_ip = target
        scan_ip = target
        geo_ips = [target]
        result.resolved_ips = [target]
    else:
        ips = await asyncio.to_thread(resolve_domain, target, config.timeout)
        result.resolved_ips = ips
        if not ips:
            result.error = f"Could not resolve domain: {target}"
            logger.warning("DNS resolution failed for %s", target)
            return result
        trace_ip = ips[0]
        scan_ip = ips[0]
        geo_ips = ips if config.all_ips else ips[:1]

    logger.info("Analyzing %s (resolved: %s)", target, result.resolved_ips)

    # Phase 2: Geo (fast, local)
    if geo_reader.available or geo_reader.asn_available:
        result.geo_results = _run_geo(geo_ips, geo_reader, cache)

    # Phase 3: Concurrent network probes
    pending: dict[str, asyncio.Task[TracerouteResult | WhoisResult | DnsRecords | list[PortResult] | TlsCertResult]] = {}

    if not config.no_traceroute:
        cached_trace = cache.get_trace(trace_ip) if cache else None
        if cached_trace is not None:
            result.traceroute = cached_trace
        else:
            pending["traceroute"] = asyncio.create_task(
                asyncio.to_thread(
                    perform_traceroute, trace_ip, config.max_hops,
                    config.timeout, config.use_scapy, config.use_tcp,
                )
            )

    if config.do_whois:
        cached_whois = cache.get_whois(scan_ip) if cache else None
        if cached_whois is not None:
            result.whois = cached_whois
        else:
            whois_timeout = min(config.timeout, 10.0)
            pending["whois"] = asyncio.create_task(
                asyncio.to_thread(whois_lookup, scan_ip, whois_timeout)
            )

    if config.dns_all and not is_ip:
        pending["dns_records"] = asyncio.create_task(
            asyncio.to_thread(query_dns_records, target, config.timeout)
        )

    if config.do_ports:
        pending["ports"] = asyncio.create_task(
            asyncio.to_thread(
                scan_ports, scan_ip, config.port_list,
                min(config.timeout, 3.0), True,
            )
        )

    if config.do_tls:
        tls_host = target if not is_ip else scan_ip
        pending["tls"] = asyncio.create_task(
            asyncio.to_thread(tls_cert_info, tls_host, 443, config.timeout)
        )

    # Collect results
    for key, task in pending.items():
        try:
            value = await asyncio.wait_for(task, timeout=config.timeout * 2)
            if key == "traceroute" and isinstance(value, TracerouteResult):
                result.traceroute = value
                if cache:
                    cache.set_trace(trace_ip, value)
            elif key == "whois" and isinstance(value, WhoisResult):
                result.whois = value
                if cache:
                    cache.set_whois(scan_ip, value)
            elif key == "dns_records" and isinstance(value, DnsRecords):
                result.dns_records = value
            elif key == "ports" and isinstance(value, list):
                result.ports = value
            elif key == "tls" and isinstance(value, TlsCertResult):
                result.tls = value
        except asyncio.TimeoutError:
            if key == "traceroute":
                result.traceroute = TracerouteResult(
                    target=trace_ip, success=False, error="Traceroute timed out",
                )
            elif key == "whois":
                result.whois = WhoisResult(
                    ip=scan_ip, success=False, error="WHOIS lookup timed out",
                )
            task.cancel()

    logger.info("Completed analysis for %s", target)
    return result


def _run_geo(
    ips: list[str], reader: GeoIPReader, cache: ResultCache | None,
) -> list[GeoResult]:
    results: list[GeoResult] = []
    for ip in ips:
        cached = cache.get_geo(ip) if cache else None
        if cached is not None:
            results.append(cached)
        else:
            geo = reader.lookup(ip)
            results.append(geo)
            if cache:
                cache.set_geo(ip, geo)
    return results
