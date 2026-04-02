# Copyright (c) 2024 prodrom3 / radamic
# Licensed under the MIT License.
# Last updated: 2026-04-02

"""Export results to CSV, HTML, and geo map formats."""

import csv
import io
import json
from pathlib import Path
from typing import Any

from core.models import AnalysisResult


def export_csv(results: list[AnalysisResult], path: str) -> None:
    """Export results to a CSV file."""
    rows: list[dict[str, Any]] = []
    for r in results:
        base = {"target": r.target, "is_ip": r.is_ip, "error": r.error or ""}
        base["resolved_ips"] = "; ".join(r.resolved_ips)

        for geo in r.geo_results or []:
            row = {**base}
            row["ip"] = geo.ip
            row["city"] = geo.city
            row["country"] = geo.country
            row["region"] = geo.region or ""
            row["latitude"] = geo.latitude or ""
            row["longitude"] = geo.longitude or ""
            row["asn"] = geo.asn or ""
            row["asn_org"] = geo.asn_org or ""
            rows.append(row)

        if not r.geo_results:
            rows.append(base)

    if not rows:
        return

    fieldnames = list(rows[0].keys())
    # Ensure all keys from all rows are included
    for row in rows:
        for key in row:
            if key not in fieldnames:
                fieldnames.append(key)

    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def export_html(results: list[AnalysisResult], path: str) -> None:
    """Export results to a self-contained HTML report."""
    html = _build_html(results)
    Path(path).write_text(html, encoding="utf-8")


def _build_html(results: list[AnalysisResult]) -> str:
    """Build HTML report string."""
    rows = ""
    for r in results:
        ips = ", ".join(r.resolved_ips) if r.resolved_ips else "-"
        geo_parts: list[str] = []
        for g in r.geo_results:
            loc = f"{g.city}, {g.country}"
            if g.asn:
                loc += f" (AS{g.asn})"
            geo_parts.append(loc)
        geo_str = "<br>".join(geo_parts) if geo_parts else "-"

        trace_str = "-"
        if r.traceroute and r.traceroute.success:
            trace_str = f"{len(r.traceroute.hops)} hops"
        elif r.traceroute:
            trace_str = r.traceroute.error or "Failed"

        ports_str = "-"
        if r.ports:
            open_ports = [p for p in r.ports if p.open]
            if open_ports:
                ports_str = ", ".join(f"{p.port}/{p.service}" for p in open_ports)
            else:
                ports_str = "None open"

        tls_str = "-"
        if r.tls and r.tls.success:
            tls_str = r.tls.issuer or "Valid"
            if r.tls.self_signed:
                tls_str = "Self-signed"

        error_str = r.error or ""

        rows += f"""<tr>
            <td>{r.target}</td><td>{ips}</td><td>{geo_str}</td>
            <td>{trace_str}</td><td>{ports_str}</td><td>{tls_str}</td>
            <td>{error_str}</td>
        </tr>\n"""

    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>ArgoNet Report</title>
<style>
body {{ font-family: system-ui, sans-serif; margin: 2em; background: #f5f5f5; }}
h1 {{ color: #2c3e50; }}
table {{ border-collapse: collapse; width: 100%; background: white; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
th {{ background: #2c3e50; color: white; padding: 10px; text-align: left; }}
td {{ padding: 8px 10px; border-bottom: 1px solid #eee; }}
tr:hover {{ background: #f0f7ff; }}
</style></head><body>
<h1>ArgoNet Report</h1>
<p>{len(results)} target(s) analyzed</p>
<table>
<tr><th>Target</th><th>IPs</th><th>Geolocation</th><th>Traceroute</th><th>Ports</th><th>TLS</th><th>Error</th></tr>
{rows}
</table></body></html>"""


def export_map(results: list[AnalysisResult], path: str) -> None:
    """Export a geo map as a self-contained HTML file with Leaflet."""
    markers: list[dict[str, Any]] = []
    for r in results:
        for g in r.geo_results:
            if g.latitude is not None and g.longitude is not None:
                markers.append({
                    "lat": g.latitude,
                    "lon": g.longitude,
                    "label": f"{r.target} - {g.city}, {g.country}",
                    "ip": g.ip,
                })

    markers_json = json.dumps(markers)

    html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>ArgoNet Map</title>
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"/>
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
<style>body{{margin:0}}#map{{height:100vh;width:100vw}}</style>
</head><body>
<div id="map"></div>
<script>
var map = L.map('map').setView([20, 0], 2);
L.tileLayer('https://{{s}}.tile.openstreetmap.org/{{z}}/{{x}}/{{y}}.png', {{
    attribution: 'OpenStreetMap'
}}).addTo(map);
var markers = {markers_json};
markers.forEach(function(m) {{
    L.marker([m.lat, m.lon]).addTo(map).bindPopup('<b>' + m.label + '</b><br>' + m.ip);
}});
if (markers.length > 0) {{
    var bounds = markers.map(function(m) {{ return [m.lat, m.lon]; }});
    map.fitBounds(bounds, {{padding: [50, 50]}});
}}
</script></body></html>"""

    Path(path).write_text(html, encoding="utf-8")
