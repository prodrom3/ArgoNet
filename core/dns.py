# Copyright (c) 2024 prodrom3 / radamic
# Licensed under the MIT License.
# Last updated: 2026-04-02

"""DNS record queries using nslookup (cross-platform, no dependencies)."""

import re
import subprocess

from core.models import DnsRecords

_RECORD_TYPES = ("MX", "TXT", "NS", "SOA", "CNAME")


def _run_nslookup(domain: str, record_type: str, timeout: float = 10.0) -> str:
    """Run nslookup for a specific record type."""
    try:
        proc = subprocess.run(
            ["nslookup", f"-type={record_type}", domain],
            capture_output=True, text=True, timeout=timeout,
        )
        return proc.stdout + proc.stderr
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return ""


def _parse_mx(output: str) -> list[str]:
    """Parse MX records from nslookup output."""
    results: list[str] = []
    for match in re.finditer(r"mail\s+exchanger\s*=\s*(.+)", output, re.IGNORECASE):
        results.append(match.group(1).strip().rstrip("."))
    return results


def _parse_txt(output: str) -> list[str]:
    """Parse TXT records from nslookup output."""
    results: list[str] = []
    for match in re.finditer(r'text\s*=\s*"(.+?)"', output, re.IGNORECASE):
        results.append(match.group(1))
    return results


def _parse_ns(output: str) -> list[str]:
    """Parse NS records from nslookup output."""
    results: list[str] = []
    for match in re.finditer(r"nameserver\s*=\s*(.+)", output, re.IGNORECASE):
        results.append(match.group(1).strip().rstrip("."))
    return results


def _parse_soa(output: str) -> str | None:
    """Parse SOA record from nslookup output."""
    match = re.search(
        r"primary name server\s*=\s*(.+?)(?:\n|\r|$)", output, re.IGNORECASE,
    )
    if match:
        return match.group(1).strip().rstrip(".")
    match = re.search(r"origin\s*=\s*(.+?)(?:\n|\r|$)", output, re.IGNORECASE)
    if match:
        return match.group(1).strip().rstrip(".")
    return None


def _parse_cname(output: str) -> list[str]:
    """Parse CNAME records from nslookup output."""
    results: list[str] = []
    for match in re.finditer(r"canonical name\s*=\s*(.+)", output, re.IGNORECASE):
        results.append(match.group(1).strip().rstrip("."))
    return results


def query_dns_records(domain: str, timeout: float = 10.0) -> DnsRecords:
    """Query all DNS record types for a domain."""
    records = DnsRecords(domain=domain)

    mx_out = _run_nslookup(domain, "MX", timeout)
    records.mx = _parse_mx(mx_out)

    txt_out = _run_nslookup(domain, "TXT", timeout)
    records.txt = _parse_txt(txt_out)

    ns_out = _run_nslookup(domain, "NS", timeout)
    records.ns = _parse_ns(ns_out)

    soa_out = _run_nslookup(domain, "SOA", timeout)
    records.soa = _parse_soa(soa_out)

    cname_out = _run_nslookup(domain, "CNAME", timeout)
    records.cname = _parse_cname(cname_out)

    return records
