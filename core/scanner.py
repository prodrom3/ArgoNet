# Copyright (c) 2024 prodrom3 / radamic
# Licensed under the MIT License.
# Last updated: 2026-04-02

"""Port scanning, banner grabbing, and TLS certificate inspection."""

import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeout

from core.models import PortResult, TlsCertResult

# Common ports and their service names
COMMON_PORTS: dict[int, str] = {
    21: "ftp", 22: "ssh", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 143: "imap", 443: "https",
    993: "imaps", 995: "pop3s", 3306: "mysql", 3389: "rdp",
    5432: "postgres", 8080: "http-alt", 8443: "https-alt",
}

_HTTP_PORTS = {80, 8080, 8443, 443}


def _scan_single_port(
    ip: str, port: int, timeout: float, grab: bool,
) -> PortResult:
    """Scan a single TCP port with optional banner grab."""
    service = COMMON_PORTS.get(port, "unknown")
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            banner = None
            if grab:
                banner = _grab_banner(sock, ip, port, timeout)
            return PortResult(port=port, open=True, service=service, banner=banner)
    except (OSError, TimeoutError):
        return PortResult(port=port, open=False, service=service)


def _grab_banner(sock: socket.socket, ip: str, port: int, timeout: float) -> str | None:
    """Read service banner from an open connection."""
    try:
        sock.settimeout(min(timeout, 3.0))
        if port in _HTTP_PORTS:
            sock.sendall(f"HEAD / HTTP/1.0\r\nHost: {ip}\r\n\r\n".encode())
        data = sock.recv(1024)
        if data:
            text = data.decode("utf-8", errors="replace").strip()
            # Return first line only for cleanliness
            return text.split("\n")[0].strip()[:200]
    except (OSError, TimeoutError):
        pass
    return None


def scan_ports(
    ip: str,
    ports: list[int] | None = None,
    timeout: float = 2.0,
    grab_banners: bool = True,
    workers: int = 16,
) -> list[PortResult]:
    """Scan multiple TCP ports concurrently."""
    target_ports = ports or list(COMMON_PORTS.keys())

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(_scan_single_port, ip, port, timeout, grab_banners): port
            for port in target_ports
        }
        results: list[PortResult] = []
        for future in futures:
            try:
                results.append(future.result(timeout=timeout + 5))
            except (FuturesTimeout, Exception):
                port = futures[future]
                results.append(PortResult(
                    port=port, open=False,
                    service=COMMON_PORTS.get(port, "unknown"),
                ))

    results.sort(key=lambda r: r.port)
    return results


def _format_dn(dn_tuples: tuple[tuple[tuple[str, str], ...], ...]) -> str:
    """Format a certificate distinguished name tuple into a readable string."""
    parts: list[str] = []
    for rdn in dn_tuples:
        for attr_type, attr_value in rdn:
            parts.append(f"{attr_type}={attr_value}")
    return ", ".join(parts)


def tls_cert_info(host: str, port: int = 443, timeout: float = 5.0) -> TlsCertResult:
    """Inspect the TLS certificate of a host."""
    # Try with verification first (gives full cert details)
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert: dict[str, object] = ssock.getpeercert() or {}  # type: ignore[assignment]
                issuer_raw = cert.get("issuer", ())
                subject_raw = cert.get("subject", ())
                san_raw = cert.get("subjectAltName", ())
                issuer_str = _format_dn(issuer_raw) if isinstance(issuer_raw, tuple) else str(issuer_raw)
                subject_str = _format_dn(subject_raw) if isinstance(subject_raw, tuple) else str(subject_raw)
                sans: list[str] = []
                if isinstance(san_raw, tuple):
                    for pair in san_raw:
                        if isinstance(pair, tuple) and len(pair) == 2 and pair[0] == "DNS":
                            sans.append(str(pair[1]))
                return TlsCertResult(
                    host=host,
                    success=True,
                    issuer=issuer_str,
                    subject=subject_str,
                    not_before=str(cert.get("notBefore", "")),
                    not_after=str(cert.get("notAfter", "")),
                    sans=sans,
                    self_signed=False,
                    protocol=ssock.version(),
                )
    except ssl.SSLCertVerificationError:
        # Self-signed or invalid cert - connect without verification
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    return TlsCertResult(
                        host=host,
                        success=True,
                        self_signed=True,
                        protocol=ssock.version(),
                        issuer="Unverified (self-signed or invalid)",
                        subject="Unverified",
                    )
        except Exception as e:
            return TlsCertResult(host=host, success=False, error=str(e))
    except Exception as e:
        return TlsCertResult(host=host, success=False, error=str(e))
