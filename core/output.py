# Copyright (c) 2024 prodrom3 / radamic
# Licensed under the MIT License.
# Last updated: 2026-04-02

"""Output rendering for ArgoNet results."""

import io
import json
import os
import sys
from typing import IO, Any

from core.models import (
    AnalysisResult, DnsRecords, GeoResult, PortResult,
    TlsCertResult, TracerouteResult, WhoisResult,
)


class Color:
    BOLD = "\033[1m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    CYAN = "\033[96m"
    DIM = "\033[2m"
    RESET = "\033[0m"

    @classmethod
    def enabled(cls, stream: IO[str] | None = None) -> bool:
        s = stream or sys.stdout
        if os.environ.get("NO_COLOR"):
            return False
        return hasattr(s, "isatty") and s.isatty()


class Renderer:
    def __init__(
        self,
        out: IO[str] | None = None,
        err: IO[str] | None = None,
        quiet: bool = False,
    ) -> None:
        self._out = out or sys.stdout
        self._err = err or sys.stderr
        self._quiet = quiet

    def _c(self, text: str, color: str) -> str:
        if Color.enabled(self._out):
            return f"{color}{text}{Color.RESET}"
        return text

    # -- Format methods (return str) ---------------------------------------

    def format_geo(self, result: GeoResult) -> str:
        parts = [result.city]
        if result.region:
            parts.append(result.region)
        parts.append(result.country)
        location = ", ".join(parts)
        if result.found:
            line = f"    {result.ip}  ->  {location}"
            if result.latitude is not None and result.longitude is not None:
                line += f"  ({result.latitude}, {result.longitude})"
        else:
            line = f"    {result.ip}  ->  " + self._c(f"{result.city}, {result.country}", Color.YELLOW)
        if result.asn is not None:
            line += f"  AS{result.asn}"
            if result.asn_org:
                line += f" ({result.asn_org})"
        return line

    def format_error(self, message: str) -> str:
        return self._c(f"  Error: {message}", Color.RED)

    def format_analysis(self, result: AnalysisResult, show_db_warning: bool = False) -> str:
        buf = io.StringIO()
        saved = self._out
        self._out = buf
        try:
            self._render_analysis(result, show_db_warning)
        finally:
            self._out = saved
        return buf.getvalue()

    def format_json(self, results: list[AnalysisResult]) -> str:
        output: dict[str, Any]
        if len(results) == 1:
            output = results[0].to_dict()
        else:
            output = {"results": [r.to_dict() for r in results]}
        return json.dumps(output, indent=2)

    # -- Print methods -----------------------------------------------------

    def progress(self, current: int, total: int, target: str) -> None:
        if self._quiet:
            return
        print(
            self._c(f"  [{current}/{total}]", Color.DIM) + f" analyzing: {target}",
            file=self._err, flush=True,
        )

    def geo(self, result: GeoResult) -> None:
        print(self.format_geo(result), file=self._out)

    def dns(self, domain: str, ips: list[str]) -> None:
        self._section("DNS Resolution")
        if ips:
            for ip in ips:
                print(f"    {domain}  ->  {ip}", file=self._out)
        else:
            print(self._c(f"    No IPs found for {domain}", Color.RED), file=self._out)

    def dns_records(self, records: DnsRecords) -> None:
        self._section(f"DNS Records for {records.domain}")
        if records.ns:
            print(f"    NS:    {', '.join(records.ns)}", file=self._out)
        if records.mx:
            print(f"    MX:    {', '.join(records.mx)}", file=self._out)
        if records.cname:
            print(f"    CNAME: {', '.join(records.cname)}", file=self._out)
        if records.soa:
            print(f"    SOA:   {records.soa}", file=self._out)
        if records.txt:
            for txt in records.txt:
                print(f"    TXT:   {txt}", file=self._out)
        if not any([records.ns, records.mx, records.cname, records.soa, records.txt]):
            print(self._c("    No additional records found", Color.YELLOW), file=self._out)

    def traceroute(self, result: TracerouteResult) -> None:
        self._section(f"Traceroute to {result.target}")
        if not result.success:
            print(self._c(f"    {result.error}", Color.RED), file=self._out)
            return
        if not result.hops:
            print(self._c("    No hops recorded", Color.YELLOW), file=self._out)
            return
        for hop in result.hops:
            rtt_str = f"{hop.rtt} ms" if hop.rtt is not None else "* ms"
            host_str = f"  ({hop.hostname})" if hop.hostname else ""
            print(f"    {hop.ttl:>3}  {hop.ip:<20}  {rtt_str}{host_str}", file=self._out)

    def whois(self, result: WhoisResult) -> None:
        self._section(f"WHOIS for {result.ip}")
        if not result.success:
            print(self._c(f"    {result.error}", Color.RED), file=self._out)
            return
        if result.org:
            print(f"    Organization:  {result.org}", file=self._out)
        if result.netname:
            print(f"    Network Name:  {result.netname}", file=self._out)
        if result.cidr:
            print(f"    CIDR/Range:    {result.cidr}", file=self._out)
        if result.description:
            print(f"    Description:   {result.description}", file=self._out)

    def ports(self, results: list[PortResult]) -> None:
        self._section("Port Scan")
        open_ports = [p for p in results if p.open]
        closed_count = len(results) - len(open_ports)
        if not open_ports:
            print(self._c(f"    No open ports found ({closed_count} closed)", Color.YELLOW), file=self._out)
            return
        for p in open_ports:
            line = f"    {p.port:>5}/{p.service:<12} " + self._c("open", Color.GREEN)
            if p.banner:
                line += f"  {p.banner}"
            print(line, file=self._out)
        if closed_count > 0:
            print(self._c(f"    ({closed_count} closed ports not shown)", Color.DIM), file=self._out)

    def tls_cert(self, result: TlsCertResult) -> None:
        self._section(f"TLS Certificate for {result.host}")
        if not result.success:
            print(self._c(f"    {result.error}", Color.RED), file=self._out)
            return
        if result.self_signed:
            print(self._c("    WARNING: Self-signed or unverified certificate", Color.YELLOW), file=self._out)
        if result.subject:
            print(f"    Subject:    {result.subject}", file=self._out)
        if result.issuer:
            print(f"    Issuer:     {result.issuer}", file=self._out)
        if result.not_before:
            print(f"    Not Before: {result.not_before}", file=self._out)
        if result.not_after:
            print(f"    Not After:  {result.not_after}", file=self._out)
        if result.sans:
            print(f"    SANs:       {', '.join(result.sans[:10])}", file=self._out)
            if len(result.sans) > 10:
                print(f"                ... and {len(result.sans) - 10} more", file=self._out)
        if result.protocol:
            print(f"    Protocol:   {result.protocol}", file=self._out)

    def diff_changes(self, changes: list[dict[str, Any]]) -> None:
        self._section("Changes from previous scan")
        if not changes:
            print(self._c("    No changes detected", Color.GREEN), file=self._out)
            return
        for c in changes:
            change_type = c["change"]
            target = c["target"]
            if change_type == "new":
                print(self._c(f"    + {target}: {c['details']}", Color.GREEN), file=self._out)
            elif change_type == "removed":
                print(self._c(f"    - {target}: {c['details']}", Color.RED), file=self._out)
            elif change_type == "changed":
                field = c.get("field", "")
                print(f"    ~ {target}.{field}: {c.get('old', '')} -> {c.get('new', '')}", file=self._out)
            elif change_type == "added":
                field = c.get("field", "")
                print(self._c(f"    + {target}.{field}: {c.get('value', '')}", Color.GREEN), file=self._out)

    def error(self, message: str) -> None:
        print(self.format_error(message), file=self._out)

    def db_warning(self) -> None:
        print(self._c("  Warning: No GeoLite2 database found.", Color.YELLOW), file=self._out)
        print(self._c("  Provide --db PATH or set GEOIP_DB_PATH env var.", Color.YELLOW), file=self._out)
        print(self._c("  Download from: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data", Color.DIM), file=self._out)

    def analysis(self, result: AnalysisResult, show_db_warning: bool = False) -> None:
        self._render_analysis(result, show_db_warning)

    def json_output(self, results: list[AnalysisResult]) -> None:
        print(self.format_json(results), file=self._out)

    # -- Internal ----------------------------------------------------------

    def _header(self, target: str) -> None:
        print(file=self._out)
        print(self._c(f"  ArgoNet - Analyzing: {target}", Color.BOLD + Color.CYAN), file=self._out)
        print(self._c("  " + "-" * 40, Color.DIM), file=self._out)

    def _section(self, title: str) -> None:
        print(file=self._out)
        print(self._c(f"  [{title}]", Color.BOLD), file=self._out)

    def _footer(self) -> None:
        print(file=self._out)

    def _render_analysis(self, result: AnalysisResult, show_db_warning: bool) -> None:
        self._header(result.target)
        if show_db_warning:
            self.db_warning()
        if result.error:
            self.error(result.error)
            self._footer()
            return
        if not result.is_ip:
            self.dns(result.target, result.resolved_ips)
        if result.dns_records:
            self.dns_records(result.dns_records)
        if result.geo_results:
            self._section("Geolocation")
            for g in result.geo_results:
                self.geo(g)
        if result.ports:
            self.ports(result.ports)
        if result.tls:
            self.tls_cert(result.tls)
        if result.traceroute:
            self.traceroute(result.traceroute)
        if result.whois:
            self.whois(result.whois)
        self._footer()
