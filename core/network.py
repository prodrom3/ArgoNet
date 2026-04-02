# Copyright (c) 2024 prodrom3 / radamic
# Licensed under the MIT License.
# Last updated: 2026-04-02

"""Network operations: DNS resolution, WHOIS, IP validation, reverse DNS."""

import logging
import re
import socket
import time
import threading
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeout

from core.models import WhoisResult

logger = logging.getLogger("argonet")


# ---------------------------------------------------------------------------
# IP validation
# ---------------------------------------------------------------------------

def validate_ip(address: str) -> bool:
    """Check if a string is a valid IPv4 or IPv6 address."""
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            socket.inet_pton(family, address)
            return True
        except (socket.error, OSError):
            continue
    return False


# ---------------------------------------------------------------------------
# DNS resolution (IPv4 + IPv6 via getaddrinfo)
# ---------------------------------------------------------------------------

def _resolve_sync(domain: str) -> list[str]:
    """Resolve a domain to unique IP addresses (A + AAAA records)."""
    results = socket.getaddrinfo(domain, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    return list(dict.fromkeys(str(r[4][0]) for r in results))


def resolve_domain(domain: str, timeout: float | None = None) -> list[str]:
    """Resolve a domain name to its IP addresses with optional timeout."""
    if timeout is not None:
        with ThreadPoolExecutor(max_workers=1) as pool:
            try:
                return pool.submit(_resolve_sync, domain).result(timeout=timeout)
            except (FuturesTimeout, socket.gaierror, OSError):
                return []
    try:
        return _resolve_sync(domain)
    except (socket.gaierror, OSError):
        return []


# ---------------------------------------------------------------------------
# Reverse DNS
# ---------------------------------------------------------------------------

def reverse_dns(ip: str) -> str | None:
    """Perform a reverse DNS lookup on an IP address."""
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname if hostname != ip else None
    except (socket.herror, socket.gaierror, OSError):
        return None


# ---------------------------------------------------------------------------
# WHOIS lookup (raw socket, no external dependencies)
# ---------------------------------------------------------------------------

_WHOIS_SERVERS: dict[str, str] = {
    "arin": "whois.arin.net",
    "ripe": "whois.ripe.net",
    "apnic": "whois.apnic.net",
    "lacnic": "whois.lacnic.net",
    "afrinic": "whois.afrinic.net",
}

_ALLOWED_WHOIS_SERVERS = set(_WHOIS_SERVERS.values())

_REFERRAL_PATTERN = re.compile(
    r"(?:ReferralServer|refer):\s*(?:whois://)?(\S+)", re.IGNORECASE,
)

_FIELD_PATTERNS: dict[str, re.Pattern[str]] = {
    "netname": re.compile(r"(?:NetName|netname):\s*(.+)", re.IGNORECASE),
    "org": re.compile(r"(?:OrgName|org-name|Organisation|organization|org):\s*(.+)", re.IGNORECASE),
    "cidr": re.compile(r"(?:CIDR|inetnum|inet6num|NetRange):\s*(.+)", re.IGNORECASE),
    "description": re.compile(r"(?:OrgTechName|descr|Comment):\s*(.+)", re.IGNORECASE),
}

_WHOIS_MAX_QUERIES = 10
_WHOIS_WINDOW_SECS = 60.0
_whois_timestamps: list[float] = []
_whois_lock = threading.Lock()
_WHOIS_MAX_RESPONSE_BYTES = 64 * 1024


def _sanitize_whois_query(query: str) -> str:
    """Strip control characters and newlines from a WHOIS query string."""
    return re.sub(r"[\r\n\x00-\x1f\x7f]", "", query).strip()


def _is_allowed_whois_server(server: str) -> bool:
    """Check if a WHOIS server is in the allowed list."""
    return server.lower() in _ALLOWED_WHOIS_SERVERS


def _whois_rate_limit() -> bool:
    """Check and enforce WHOIS rate limit. Returns True if allowed."""
    now = time.monotonic()
    with _whois_lock:
        while _whois_timestamps and _whois_timestamps[0] < now - _WHOIS_WINDOW_SECS:
            _whois_timestamps.pop(0)
        if len(_whois_timestamps) >= _WHOIS_MAX_QUERIES:
            return False
        _whois_timestamps.append(now)
        return True


def _whois_query(server: str, query: str, timeout: float = 10.0) -> str:
    """Send a raw WHOIS query to the given server with size limit."""
    safe_query = _sanitize_whois_query(query)
    with socket.create_connection((server, 43), timeout=timeout) as sock:
        sock.sendall(f"{safe_query}\r\n".encode())
        chunks: list[bytes] = []
        total = 0
        while total < _WHOIS_MAX_RESPONSE_BYTES:
            data = sock.recv(4096)
            if not data:
                break
            chunks.append(data)
            total += len(data)
    return b"".join(chunks).decode("utf-8", errors="replace")


def whois_lookup(ip: str, timeout: float = 10.0) -> WhoisResult:
    """Perform a WHOIS lookup for an IP address with rate limiting."""
    if not _whois_rate_limit():
        return WhoisResult(
            ip=ip, success=False,
            error="WHOIS rate limit exceeded (max 10 queries per 60 seconds)",
        )

    try:
        raw = _whois_query(_WHOIS_SERVERS["arin"], f"n {ip}", timeout)

        referral_match = _REFERRAL_PATTERN.search(raw)
        if referral_match:
            referral_server = referral_match.group(1).split(":")[0].lower()
            if _is_allowed_whois_server(referral_server):
                try:
                    raw = _whois_query(referral_server, ip, timeout)
                except (OSError, TimeoutError):
                    pass

        fields: dict[str, str] = {}
        for field_name, pattern in _FIELD_PATTERNS.items():
            match = pattern.search(raw)
            if match:
                fields[field_name] = match.group(1).strip()

        return WhoisResult(
            ip=ip, success=True,
            netname=fields.get("netname"), org=fields.get("org"),
            cidr=fields.get("cidr"), description=fields.get("description"),
        )
    except (OSError, TimeoutError) as e:
        return WhoisResult(ip=ip, success=False, error=f"WHOIS lookup failed: {e}")
    except Exception as e:
        return WhoisResult(ip=ip, success=False, error=f"WHOIS error: {e}")
