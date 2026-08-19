"""
Report rendering and export.

Turns one or more HostReport objects into a human-readable text report,
plus optional structured JSON/CSV exports suitable for feeding into
ticketing systems, spreadsheets, or other tooling.
"""

from __future__ import annotations

import csv
import io
import json
import os
import time
from typing import List

from .db import SEVERITY_ORDER, SEVERITY_WEIGHT, get_db
from .scanner import HostReport


def get_port_info(port: int):
    """Look up risk metadata for a port via the SQLite-backed database."""
    return get_db().get_port_info(port)

_BANNER = "=" * 80
_RULE = "-" * 80


def _severity_counts(report: HostReport) -> dict:
    counts = {sev: 0 for sev in SEVERITY_ORDER}
    for result in report.open_ports:
        severity = get_port_info(result.port)["severity"]
        counts[severity] = counts.get(severity, 0) + 1
    return counts


def render_text(reports: List[HostReport]) -> str:
    """Render a full multi-host audit as a human-readable text report."""
    lines: List[str] = []

    def emit(line: str = "") -> None:
        lines.append(line)

    emit(_BANNER)
    emit(" NETPRETER SECURITY AUDIT REPORT")
    emit(f" Generated: {time.strftime('%Y-%m-%d %H:%M:%S %Z')}")
    emit(f" Hosts scanned: {len(reports)}")
    emit(_BANNER)

    grand_totals = {sev: 0 for sev in SEVERITY_ORDER}

    for report in reports:
        emit(f"\nTARGET: {report.host}")
        emit(f"Duration: {report.duration_seconds:.2f}s | Ports probed: {report.ports_scanned} | Open: {len(report.open_ports)}")
        emit(_RULE)

        if report.error:
            emit(f"[-] Scan error: {report.error}")
            continue

        if not report.open_ports:
            emit("[+] No open ports detected from the scan list. Perimeter posture appears restrictive.")
            continue

        # Highest-risk findings first.
        ordered = sorted(
            report.open_ports,
            key=lambda r: SEVERITY_WEIGHT.get(get_port_info(r.port)["severity"], 99),
        )

        for result in ordered:
            info = get_port_info(result.port)
            grand_totals[info["severity"]] = grand_totals.get(info["severity"], 0) + 1

            emit(f"\n[!] Port {result.port}/TCP: {info['service']}")
            emit(f"    Severity:    [{info['severity'].upper()}]")
            emit(f"    Observation: {info['description']}")
            if result.banner:
                emit(f"    Banner:      {result.banner}")
            emit(f"    Remediation: {info['remediation']}")

        counts = _severity_counts(report)
        emit("")
        emit(f"Host summary: " + ", ".join(f"{sev}: {n}" for sev, n in counts.items() if n))

    emit("\n" + _BANNER)
    emit(" OVERALL SUMMARY")
    for sev in SEVERITY_ORDER:
        if grand_totals[sev]:
            emit(f"  - {sev}: {grand_totals[sev]}")
    if not any(grand_totals.values()):
        emit("  - No findings across all scanned hosts.")
    emit(_RULE)
    emit(" RECOMMENDED NEXT STEPS")
    emit("  1. Apply firewall rules (iptables/nftables/UFW/cloud Security Groups) to close unused ports.")
    emit("  2. Replace or reconfigure legacy/plaintext protocols with encrypted alternatives.")
    emit("  3. Re-run this audit after remediation to confirm exposure has been closed.")
    emit("  4. Follow up with an authenticated configuration review for any service left intentionally open.")
    emit(_BANNER)

    return "\n".join(lines)


def to_json(reports: List[HostReport]) -> str:
    """Serialize the audit results to a structured JSON document."""
    payload = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "hosts": [],
    }
    for report in reports:
        host_payload = {
            "host": report.host,
            "duration_seconds": round(report.duration_seconds, 3),
            "ports_scanned": report.ports_scanned,
            "error": report.error,
            "findings": [],
        }
        for result in report.open_ports:
            info = get_port_info(result.port)
            host_payload["findings"].append(
                {
                    "port": result.port,
                    "protocol": "tcp",
                    "service": info["service"],
                    "severity": info["severity"],
                    "description": info["description"],
                    "remediation": info["remediation"],
                    "banner": result.banner,
                }
            )
        payload["hosts"].append(host_payload)
    return json.dumps(payload, indent=2)


def to_csv(reports: List[HostReport]) -> str:
    """Serialize findings (one row per open port) to CSV."""
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["host", "port", "protocol", "service", "severity", "description", "remediation", "banner"])
    for report in reports:
        for result in report.open_ports:
            info = get_port_info(result.port)
            writer.writerow(
                [
                    report.host,
                    result.port,
                    "tcp",
                    info["service"],
                    info["severity"],
                    info["description"],
                    info["remediation"],
                    result.banner or "",
                ]
            )
    return buffer.getvalue()


def save_report(reports: List[HostReport], primary_target: str, fmt: str = "text", log_dir: str = "logs") -> str:
    """
    Render the report in the requested format and persist it to a
    timestamped file under log_dir. Returns the path written.
    """
    os.makedirs(log_dir, exist_ok=True)
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    sanitized_host = primary_target.replace(".", "_").replace(":", "_").replace("/", "_")

    fmt = fmt.lower()
    if fmt == "json":
        content, ext = to_json(reports), "json"
    elif fmt == "csv":
        content, ext = to_csv(reports), "csv"
    else:
        content, ext = render_text(reports), "log"

    filename = os.path.join(log_dir, f"audit_{sanitized_host}_{timestamp}.{ext}")
    with open(filename, "w", encoding="utf-8", newline="") as fh:
        fh.write(content)
    return filename
