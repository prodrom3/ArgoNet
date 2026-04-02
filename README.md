# ArgoNet

[![CI](https://github.com/prodrom3/ArgoNet/actions/workflows/ci.yml/badge.svg)](https://github.com/prodrom3/ArgoNet/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![mypy: strict](https://img.shields.io/badge/mypy-strict-blue.svg)](https://mypy-lang.org/)

ArgoNet is a robust networking tool that combines geolocation, domain resolution, and network path analysis (traceroute) to provide comprehensive insights into network entities. It also supports DNS enumeration, port scanning, TLS inspection, WHOIS lookups, ASN identification, multiple concurrent targets, CIDR ranges, export to CSV/HTML/map, and change detection against previous scans.

<p align="center">
  <img width="460" height="460" src="https://github.com/prodrom3/ArgoNet/assets/7604466/6343df52-d5e6-4c1c-b1cf-3e904b694331">
</p>

## Features

- **IP Geolocation** - City, region, country, coordinates via GeoLite2
- **ASN Identification** - Autonomous System Number and organization via GeoLite2 ASN
- **DNS Resolution** - A + AAAA records (IPv4 and IPv6)
- **DNS Enumeration** - MX, TXT, NS, SOA, CNAME records
- **Traceroute** - System traceroute (default, no admin needed on Windows) or scapy (ICMP/TCP SYN)
- **Port Scanning** - TCP connect scan on common ports with banner grabbing
- **TLS Inspection** - Certificate issuer, expiry, SANs, self-signed detection
- **WHOIS Lookup** - Organization, netname, CIDR from RIR databases (rate-limited)
- **CIDR Support** - Expand `192.168.1.0/24` into individual targets
- **Multiple Targets** - Concurrent analysis with configurable workers
- **Export** - CSV, self-contained HTML report, and Leaflet geo map
- **Diff Mode** - Compare current results against a previous JSON scan
- **JSON Output** - Structured output for scripting
- **Stdin Piping** - Read targets from files or pipelines
- **Graceful Shutdown** - Ctrl+C cancels pending work and outputs partial results
- **Logging** - Timestamped log files with automatic rotation

## Installation

### Prerequisites

- Python >= 3.10
- `geoip2` (required for geolocation)
- `scapy` (optional, for raw packet traceroute)

### Install

```bash
# Minimal install (uses system traceroute, no admin needed)
pip install geoip2
python argonet.py 8.8.8.8

# With scapy for advanced traceroute
pip install geoip2 scapy

# Or install as a package
pip install .           # minimal
pip install .[scapy]    # with scapy
pip install .[dev]      # with dev tools
```

### GeoLite2 Databases

Download from [MaxMind](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) (free account required):
- **GeoLite2-City.mmdb** - geolocation (city, region, country, coordinates)
- **GeoLite2-ASN.mmdb** - ASN identification (optional)

Set the path via `--db`, the `GEOIP_DB_PATH` environment variable, or place the file in your home directory.

## Usage

```bash
python argonet.py TARGET [TARGET ...] [OPTIONS]
cat targets.txt | python argonet.py [OPTIONS]
```

### Flags

| Flag | Description |
|---|---|
| `TARGET` | IPs, domains, or CIDR ranges (also reads from stdin) |
| `--db PATH` | Path to GeoLite2-City.mmdb (or `GEOIP_DB_PATH` env var) |
| `--asn-db PATH` | Path to GeoLite2-ASN.mmdb |
| `--dns-all` | Query MX, TXT, NS, SOA, CNAME records |
| `--ports [LIST]` | Scan ports (default set, or comma-separated: `--ports 22,80,443`) |
| `--tls` | Inspect TLS certificate on port 443 |
| `--whois` | WHOIS lookup (rate-limited to 10/minute) |
| `--all-ips` | Geolocate all resolved IPs, not just the first |
| `--no-traceroute` | Skip traceroute |
| `--scapy` | Use scapy for traceroute instead of system command (requires admin) |
| `--tcp` | TCP SYN traceroute (requires `--scapy`) |
| `--max-hops N` | Maximum traceroute hops (default: 20) |
| `--timeout SECS` | Network operation timeout (default: 30) |
| `--workers N` | Concurrent workers (default: 4) |
| `--json` | JSON output |
| `--csv FILE` | Export results to CSV |
| `--html FILE` | Export results to HTML report |
| `--map FILE` | Export geo map as HTML (Leaflet/OpenStreetMap) |
| `--diff FILE` | Compare results against a previous JSON file |
| `-q, --quiet` | Suppress progress output |
| `-v, --version` | Show version and exit |

### Examples

```bash
# Basic recon
python argonet.py 8.8.8.8

# Full sweep on a domain
python argonet.py --dns-all --ports --tls --whois example.com

# Multiple targets concurrently
python argonet.py 8.8.8.8 1.1.1.1 example.com

# Scan a subnet
python argonet.py --ports --no-traceroute 192.168.1.0/24

# DNS enumeration only
python argonet.py --dns-all --no-traceroute example.com

# TLS certificate check
python argonet.py --tls --no-traceroute example.com

# Geolocation with ASN and coordinates
python argonet.py --db city.mmdb --asn-db asn.mmdb --all-ips example.com

# Pipe targets from a file
cat targets.txt | python argonet.py --no-traceroute --json

# Export to HTML report and geo map
python argonet.py --html report.html --map map.html 8.8.8.8 1.1.1.1

# Export to CSV
python argonet.py --csv results.csv --no-traceroute example.com

# Track changes over time
python argonet.py --json example.com > baseline.json
# ... later ...
python argonet.py example.com --diff baseline.json

# Scapy traceroute (requires admin)
sudo python argonet.py --scapy 8.8.8.8

# JSON output for scripting
python argonet.py --json 8.8.8.8 | jq '.geolocation'
```

Note: System traceroute works without admin on Windows. Use `--scapy` for raw packet mode (requires admin/root).

## Project Structure

```
ArgoNet/
  argonet.py            - Entry point (asyncio orchestration, SIGINT, exports)
  VERSION               - Version string
  pyproject.toml        - Packaging (scapy optional)
  core/
    models.py           - Data classes (GeoResult, DnsRecords, PortResult, TlsCertResult, ...)
    geo.py              - GeoIPReader (city + ASN), bounded ResultCache
    network.py          - DNS resolution, reverse DNS, WHOIS
    dns.py              - DNS record enumeration (MX, TXT, NS, SOA, CNAME)
    scanner.py          - Port scanning, banner grabbing, TLS cert inspection
    tracer.py           - System traceroute + scapy backends
    pipeline.py         - Async analysis pipeline
    cli.py              - Argument parsing, CIDR expansion, stdin
    output.py           - Renderer class (human-readable, JSON, diff)
    logging_config.py   - Log setup with rotation
    export.py           - CSV, HTML report, geo map
    diff.py             - JSON result comparison
  tests/                - 106 unit tests + 5 integration tests
```

## Development

```bash
# Run tests
python -m pytest tests/ -v

# Run integration tests (requires network)
ARGONET_INTEGRATION=1 python -m pytest tests/test_integration.py -v

# Type checking
pip install mypy types-geoip2
mypy core/ argonet.py

# Coverage
python -m pytest tests/ --cov=core --cov-report=term

# Install in dev mode
pip install -e ".[dev]"
```

## Contributing

Contributions to ArgoNet are welcome. Please fork the repository, make improvements, and submit pull requests.

## Go Version

Looking for the Go version? See [Triton](https://github.com/prodrom3/triton).

## Author

Created by [prodrom3](https://github.com/prodrom3) / [radamic](https://github.com/radamic)

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

If you encounter any problems or have suggestions, please open an issue on the GitHub repository.
