# Copyright (c) 2024 prodrom3 / radamic
# Licensed under the MIT License.
# Last updated: 2026-04-02

"""Command-line interface for ArgoNet."""

import argparse
import ipaddress
import os
import sys
from pathlib import Path


def _read_version() -> str:
    version_file = Path(__file__).resolve().parent.parent / "VERSION"
    try:
        return version_file.read_text().strip()
    except FileNotFoundError:
        return "0.0.0"


VERSION = _read_version()


def _find_db_path(cli_value: str | None) -> str | None:
    if cli_value:
        return cli_value
    env_path = os.environ.get("GEOIP_DB_PATH")
    if env_path:
        return env_path
    common_paths = [
        Path.home() / "GeoLite2-City.mmdb",
        Path.home() / ".local" / "share" / "GeoIP" / "GeoLite2-City.mmdb",
        Path("/usr/share/GeoIP/GeoLite2-City.mmdb"),
        Path("/usr/local/share/GeoIP/GeoLite2-City.mmdb"),
    ]
    for path in common_paths:
        if path.exists():
            return str(path)
    return None


def _read_stdin_targets() -> list[str]:
    if sys.stdin.isatty():
        return []
    targets: list[str] = []
    for line in sys.stdin:
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            targets.append(stripped)
    return targets


def _expand_cidr(targets: list[str]) -> list[str]:
    """Expand CIDR notation (e.g. 192.168.1.0/24) into individual IPs."""
    expanded: list[str] = []
    for t in targets:
        try:
            net = ipaddress.ip_network(t, strict=False)
            if net.num_addresses > 1 and net.prefixlen < 128:
                expanded.extend(str(ip) for ip in net.hosts())
            else:
                expanded.append(t)
        except ValueError:
            expanded.append(t)
    return expanded


def _positive_int(value: str) -> int:
    n = int(value)
    if n < 1:
        raise argparse.ArgumentTypeError(f"must be at least 1, got {n}")
    return n


def _positive_float(value: str) -> float:
    f = float(value)
    if f <= 0:
        raise argparse.ArgumentTypeError(f"must be greater than 0, got {f}")
    return f


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="argonet",
        description="ArgoNet - Network reconnaissance toolkit.",
    )

    # Targets
    parser.add_argument(
        "targets", nargs="*", metavar="TARGET",
        help="IPs, domains, or CIDR ranges (also reads from stdin)",
    )

    # Database paths
    parser.add_argument("--db", default=None, metavar="PATH",
                        help="path to GeoLite2-City.mmdb (or GEOIP_DB_PATH env var)")
    parser.add_argument("--asn-db", default=None, metavar="PATH",
                        help="path to GeoLite2-ASN.mmdb")

    # Operation controls
    parser.add_argument("--max-hops", type=_positive_int, default=20, metavar="N",
                        help="max traceroute hops (default: 20)")
    parser.add_argument("--timeout", type=_positive_float, default=30.0, metavar="SECS",
                        help="network timeout (default: 30)")
    parser.add_argument("--workers", type=_positive_int, default=4, metavar="N",
                        help="concurrent workers (default: 4)")

    # Feature flags
    parser.add_argument("--no-traceroute", action="store_true",
                        help="skip traceroute")
    parser.add_argument("--whois", action="store_true",
                        help="include WHOIS lookup")
    parser.add_argument("--dns-all", action="store_true",
                        help="query MX, TXT, NS, SOA, CNAME records")
    parser.add_argument("--ports", nargs="?", const="default", default=None, metavar="LIST",
                        help="scan ports (default set, or comma-separated list)")
    parser.add_argument("--tls", action="store_true",
                        help="inspect TLS certificate (port 443)")
    parser.add_argument("--all-ips", action="store_true",
                        help="geolocate all resolved IPs")

    # Traceroute backend
    parser.add_argument("--tcp", action="store_true",
                        help="TCP SYN traceroute (requires --scapy)")
    parser.add_argument("--scapy", action="store_true",
                        help="use scapy for traceroute (requires admin)")

    # Output format
    parser.add_argument("--json", action="store_true", dest="json_output",
                        help="JSON output")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="suppress progress")

    # Export
    parser.add_argument("--csv", default=None, metavar="FILE",
                        help="export results to CSV file")
    parser.add_argument("--html", default=None, metavar="FILE",
                        help="export results to HTML report")
    parser.add_argument("--map", default=None, metavar="FILE",
                        help="export geo map as HTML file")

    # Diff
    parser.add_argument("--diff", default=None, metavar="FILE",
                        help="compare results against a previous JSON file")

    parser.add_argument("-v", "--version", action="version",
                        version=f"%(prog)s {VERSION}")

    args = parser.parse_args(argv)

    # Merge stdin + positional + CIDR expansion
    stdin_targets = _read_stdin_targets() if argv is None else []
    all_targets: list[str] = (args.targets or []) + stdin_targets
    all_targets = _expand_cidr(all_targets)

    if not all_targets:
        parser.print_help(sys.stderr)
        sys.exit(1)

    args.targets = all_targets
    args.db = _find_db_path(args.db)

    # Parse --ports value
    if args.ports == "default":
        args.port_list = None  # use defaults from scanner
    elif args.ports is not None:
        try:
            args.port_list = [int(p.strip()) for p in args.ports.split(",")]
        except ValueError:
            parser.error(f"invalid port list: {args.ports}")
    else:
        args.port_list = None

    return args
