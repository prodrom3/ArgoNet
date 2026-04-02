# Copyright (c) 2024 prodrom3 / radamic
# Licensed under the MIT License.
# Last updated: 2026-04-02

"""Traceroute implementations: system (default) and scapy (optional)."""

import platform
import re
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeout
from typing import Any

from core.models import TracerouteHop, TracerouteResult


# ---------------------------------------------------------------------------
# Reverse DNS enrichment (lives here to avoid circular import with network.py)
# ---------------------------------------------------------------------------

def _reverse_dns(ip: str) -> str | None:
    """Perform a reverse DNS lookup on an IP address."""
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname if hostname != ip else None
    except (socket.herror, socket.gaierror, OSError):
        return None


def enrich_hops_with_rdns(hops: list[TracerouteHop], timeout: float = 2.0) -> None:
    """Add reverse DNS hostnames to traceroute hops concurrently with timeout."""
    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = {
            pool.submit(_reverse_dns, h.ip): i
            for i, h in enumerate(hops)
        }
        for future in futures:
            try:
                hops[futures[future]].hostname = future.result(timeout=timeout)
            except (FuturesTimeout, OSError):
                pass


# ---------------------------------------------------------------------------
# System traceroute (no dependencies, no admin on Windows)
# ---------------------------------------------------------------------------

_LINUX_HOP_RE = re.compile(
    r"^\s*(\d+)\s+"
    r"([\d.]+)\s+"
    r"([\d.]+)\s+ms"
)

_WINDOWS_HOP_RE = re.compile(
    r"^\s*(\d+)\s+"
    r"(?:"
    r"([<\d]+)\s+ms\s+"
    r"[<\d]+\s+ms\s+"
    r"[<\d]+\s+ms\s+"
    r"(\S+)"
    r"|"
    r"\*"
    r")",
)


def _parse_rtt(rtt_str: str) -> float:
    """Parse an RTT string like '1.234' or '<1' to a float."""
    cleaned = rtt_str.strip().lstrip("<")
    try:
        return float(cleaned)
    except ValueError:
        return 0.0


def _parse_system_output(output: str) -> list[TracerouteHop]:
    """Parse traceroute/tracert output into TracerouteHop list."""
    hops: list[TracerouteHop] = []
    is_windows = "Tracing route" in output or "tracert" in output.lower()

    for line in output.splitlines():
        if is_windows:
            match = _WINDOWS_HOP_RE.match(line)
            if match and match.group(2):
                ttl = int(match.group(1))
                rtt = _parse_rtt(match.group(2))
                ip = match.group(3)
                hops.append(TracerouteHop(ttl=ttl, ip=ip, rtt=rtt))
        else:
            match = _LINUX_HOP_RE.match(line)
            if match:
                ttl = int(match.group(1))
                ip = match.group(2)
                rtt = _parse_rtt(match.group(3))
                hops.append(TracerouteHop(ttl=ttl, ip=ip, rtt=rtt))

    return hops


def system_traceroute(
    target: str, max_hops: int = 20, timeout: float = 2.0,
) -> TracerouteResult:
    """Run the OS traceroute/tracert command and parse the output."""
    is_windows = platform.system() == "Windows"

    if is_windows:
        cmd = ["tracert", "-d", "-h", str(max_hops), "-w", str(int(timeout * 1000)), target]
    else:
        cmd = ["traceroute", "-n", "-m", str(max_hops), "-w", str(max(1, int(timeout))), target]

    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=max_hops * timeout + 10,
        )
        hops = _parse_system_output(proc.stdout + proc.stderr)
        return TracerouteResult(target=target, success=True, hops=hops)
    except FileNotFoundError:
        tool = "tracert" if is_windows else "traceroute"
        return TracerouteResult(
            target=target, success=False,
            error=f"{tool} not found on PATH. Install it or use --scapy.",
        )
    except subprocess.TimeoutExpired:
        return TracerouteResult(
            target=target, success=False, error="Traceroute timed out",
        )
    except Exception as e:
        return TracerouteResult(
            target=target, success=False, error=f"Traceroute failed: {e}",
        )


# ---------------------------------------------------------------------------
# Scapy traceroute (optional, requires admin)
# ---------------------------------------------------------------------------

def _import_scapy_traceroute() -> Any:
    """Import scapy traceroute function, trying lighter import first."""
    try:
        import scapy.layers.inet  # noqa: F401
        from scapy.sendrecv import traceroute as scapy_tr  # type: ignore[attr-defined]
        return scapy_tr
    except ImportError:
        from scapy.all import traceroute as scapy_tr  # type: ignore[attr-defined]
        return scapy_tr


def scapy_icmp_traceroute(
    target: str, max_hops: int = 20, timeout: float = 2.0,
) -> TracerouteResult:
    """ICMP traceroute using scapy - sends all probes in parallel."""
    try:
        from scapy.layers.inet import ICMP, IP  # noqa: F811
        from scapy.sendrecv import sr
    except ImportError:
        return TracerouteResult(
            target=target, success=False,
            error="scapy is not installed. Install with: pip install scapy",
        )

    try:
        probes: Any = [IP(dst=target, ttl=ttl) / ICMP() for ttl in range(1, max_hops + 1)]
        answered: Any
        answered, _ = sr(probes, verbose=0, timeout=timeout)

        hops: list[TracerouteHop] = []
        for sent, received in answered:
            rtt = round(float(received.time - sent.sent_time) * 1000, 2)
            hops.append(TracerouteHop(ttl=sent.ttl, ip=received.src, rtt=float(rtt)))
        return TracerouteResult(target=target, success=True, hops=hops)
    except PermissionError:
        return TracerouteResult(
            target=target, success=False,
            error="Scapy traceroute requires administrative privileges. "
            "Run with sudo (Linux/macOS) or as Administrator (Windows).",
        )
    except Exception as e:
        return TracerouteResult(
            target=target, success=False, error=f"Scapy traceroute failed: {e}",
        )


def scapy_tcp_traceroute(
    target: str, max_hops: int = 20, timeout: float = 2.0,
) -> TracerouteResult:
    """TCP SYN traceroute using scapy's built-in traceroute function."""
    try:
        scapy_tr = _import_scapy_traceroute()
    except ImportError:
        return TracerouteResult(
            target=target, success=False,
            error="scapy is not installed. Install with: pip install scapy",
        )

    try:
        result, _ = scapy_tr(target, maxttl=max_hops, verbose=0, timeout=timeout)
        hops: list[TracerouteHop] = []
        for sent, received in result:
            hops.append(TracerouteHop(
                ttl=sent.ttl, ip=received.src,
                rtt=round((received.time - sent.sent_time) * 1000, 2),
            ))
        return TracerouteResult(target=target, success=True, hops=hops)
    except PermissionError:
        return TracerouteResult(
            target=target, success=False,
            error="Scapy traceroute requires administrative privileges.",
        )
    except Exception as e:
        return TracerouteResult(
            target=target, success=False, error=f"Scapy traceroute failed: {e}",
        )


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------

def perform_traceroute(
    target: str,
    max_hops: int = 20,
    timeout: float | None = None,
    use_scapy: bool = False,
    use_tcp: bool = False,
    rdns: bool = True,
) -> TracerouteResult:
    """Run traceroute using system command (default) or scapy (optional)."""
    probe_timeout = min(timeout, 5.0) if timeout else 2.0

    if use_scapy:
        if use_tcp:
            result = scapy_tcp_traceroute(target, max_hops, probe_timeout)
        else:
            result = scapy_icmp_traceroute(target, max_hops, probe_timeout)
    else:
        result = system_traceroute(target, max_hops, probe_timeout)

    if result.success and result.hops:
        result.hops.sort(key=lambda h: h.ttl)
        if rdns:
            rdns_timeout = min(timeout, 5.0) if timeout else 2.0
            enrich_hops_with_rdns(result.hops, rdns_timeout)

    return result
