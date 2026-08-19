"""
Command-line interface for Netpreter.

Supports two modes:
  1. Non-interactive: `netpreter <target> [options]` - scriptable, CI-friendly.
  2. Interactive menu: run with no arguments for a guided prompt-based flow.
"""

from __future__ import annotations

import argparse
import logging
import sys
import webbrowser
from typing import List, Sequence

from . import __version__
from .db import get_db
from .report import render_text, save_report
from .scanner import (
    TargetResolutionError,
    get_local_ip,
    resolve_targets,
    scan_targets,
)

logger = logging.getLogger("netpreter")

DEFAULT_WEB_HOST = "127.0.0.1"
DEFAULT_WEB_PORT = 5000


def parse_port_spec(spec: str) -> List[int]:
    """
    Parse a port specification string into a sorted list of unique ports.

    Accepts comma-separated ports and hyphenated ranges, e.g.:
      "22,80,443"
      "1-1024"
      "22,80,1000-2000"
    The special value "top" selects the curated risk database ports (SQLite-backed).
    """
    spec = spec.strip().lower()
    if spec in ("top", "default", ""):
        return list(get_db().get_top_ports())

    ports: set[int] = set()
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            start_s, _, end_s = chunk.partition("-")
            try:
                start, end = int(start_s), int(end_s)
            except ValueError as exc:
                raise argparse.ArgumentTypeError(f"Invalid port range '{chunk}'") from exc
            if not (0 < start <= end <= 65535):
                raise argparse.ArgumentTypeError(f"Port range '{chunk}' out of bounds (1-65535)")
            ports.update(range(start, end + 1))
        else:
            try:
                port = int(chunk)
            except ValueError as exc:
                raise argparse.ArgumentTypeError(f"Invalid port '{chunk}'") from exc
            if not (0 < port <= 65535):
                raise argparse.ArgumentTypeError(f"Port '{chunk}' out of bounds (1-65535)")
            ports.add(port)

    if not ports:
        raise argparse.ArgumentTypeError("No valid ports parsed from specification.")
    return sorted(ports)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netpreter",
        description="Multi-threaded perimeter security audit tool: scans for "
        "commonly exposed high-risk TCP services and reports remediation guidance.",
    )
    parser.add_argument(
        "target",
        nargs="?",
        help="Target host, IP, or CIDR range (e.g. example.com, 10.0.0.5, 10.0.0.0/28). "
        "Comma-separate multiple targets. Omit to launch the interactive menu.",
    )
    parser.add_argument(
        "-p", "--ports",
        default="top",
        type=parse_port_spec,
        help="Ports to scan: 'top' (curated risk database, default), a comma list, "
        "and/or ranges, e.g. '22,80,443' or '1-1024'.",
    )
    parser.add_argument(
        "-t", "--timeout",
        type=float,
        default=1.0,
        help="Per-port connection timeout in seconds (default: 1.0).",
    )
    parser.add_argument(
        "-T", "--threads",
        type=int,
        default=100,
        help="Maximum concurrent worker threads per host (default: 100).",
    )
    parser.add_argument(
        "--no-banner",
        action="store_true",
        help="Disable passive service banner capture.",
    )
    parser.add_argument(
        "-f", "--format",
        choices=["text", "json", "csv"],
        default="text",
        help="Report format for both console output and the saved log file (default: text).",
    )
    parser.add_argument(
        "-o", "--output-dir",
        default="logs",
        help="Directory to write timestamped audit logs into (default: ./logs).",
    )
    parser.add_argument(
        "--no-save",
        action="store_true",
        help="Print the report without writing it to disk.",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose (debug) logging to stderr.",
    )
    parser.add_argument(
        "--web",
        action="store_true",
        help="Launch the local Web Dashboard UI instead of scanning from the CLI.",
    )
    parser.add_argument(
        "--web-host",
        default=DEFAULT_WEB_HOST,
        help=f"Host/interface for the Web Dashboard UI (default: {DEFAULT_WEB_HOST}).",
    )
    parser.add_argument(
        "--web-port",
        type=int,
        default=DEFAULT_WEB_PORT,
        help=f"Port for the Web Dashboard UI (default: {DEFAULT_WEB_PORT}).",
    )
    parser.add_argument(
        "--no-browser",
        action="store_true",
        help="When launching the Web Dashboard UI, don't auto-open a browser tab.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"netpreter {__version__}",
    )
    return parser


def launch_web_dashboard(host: str = DEFAULT_WEB_HOST, port: int = DEFAULT_WEB_PORT, open_browser: bool = True) -> int:
    """Start the zero-dependency web dashboard server and (optionally) open a browser tab."""
    from .web_server import serve_forever

    url = f"http://{host}:{port}/"
    print(f"\n[*] Netpreter v{__version__} — Web Dashboard")
    print(f"[*] Serving on {url}")
    print("[*] Press Ctrl+C to stop.\n")

    if open_browser:
        try:
            webbrowser.open(url)
        except Exception as exc:  # pragma: no cover - best effort only
            logger.debug("Could not auto-open browser: %s", exc)

    try:
        serve_forever(host, port)
    except KeyboardInterrupt:
        print("\n[*] Web Dashboard stopped.")
    return 0


def _progress_printer(host: str, completed: int, total: int) -> None:
    if total == 0:
        return
    bar_width = 30
    filled = int(bar_width * completed / total)
    bar = "#" * filled + "-" * (bar_width - filled)
    sys.stdout.write(f"\r[*] {host}: [{bar}] {completed}/{total}")
    sys.stdout.flush()
    if completed == total:
        sys.stdout.write("\n")


def run_scan(target_spec: str, ports: Sequence[int], args: argparse.Namespace) -> int:
    """Resolve targets, run the audit, print/save the report. Returns an exit code."""
    try:
        targets = resolve_targets(target_spec)
    except TargetResolutionError as exc:
        print(f"[-] {exc}")
        return 1

    print(f"\n[*] Netpreter v{__version__} — initiating audit")
    print(f"[*] Targets ({len(targets)}): {', '.join(targets)}")
    print(f"[*] Ports queued per host: {len(ports)}")
    print("[*] Scan in progress...\n")

    reports = scan_targets(
        targets,
        ports,
        timeout=args.timeout,
        max_threads=args.threads,
        grab_banner=not args.no_banner,
        progress_callback=_progress_printer,
    )

    db = get_db()
    for report in reports:
        if not report.error:
            db.record_scan(report.host, report.duration_seconds, report.open_ports)

    if args.format == "text":
        print("\n" + render_text(reports))
    else:
        # Still show a concise console summary even when exporting structured data.
        print("\n" + render_text(reports))

    if not args.no_save:
        path = save_report(reports, targets[0], fmt=args.format, log_dir=args.output_dir)
        print(f"[*] Report saved to: {path}")

    return 0


def _scan_submenu(args: argparse.Namespace) -> None:
    while True:
        print("\n--- Run Scan ---")
        print("1. Scan Local Host (127.0.0.1)")
        print("2. Scan Local Network Interface IP")
        print("3. Scan Custom Target (IP, hostname, or CIDR range)")
        print("4. Back to Main Menu")

        choice = input("\nSelect an option [1-4]: ").strip()

        if choice == "1":
            run_scan("127.0.0.1", args.ports, args)
            return
        elif choice == "2":
            local_ip = get_local_ip()
            print(f"[*] Detected local interface IP: {local_ip}")
            run_scan(local_ip, args.ports, args)
            return
        elif choice == "3":
            target = input("Enter target IP, hostname, or CIDR range: ").strip()
            if not target:
                print("[-] Target cannot be empty.")
                continue
            run_scan(target, args.ports, args)
            return
        elif choice == "4":
            return
        else:
            print("[-] Invalid selection. Please choose an option from 1 to 4.")


def _print_history(db) -> None:
    history = db.get_scan_history(limit=20)
    if not history:
        print("\n[*] No past scans recorded yet.")
        return
    print(f"\n{'ID':<5}{'Target':<20}{'Timestamp':<22}{'Duration':<10}{'Open Ports'}")
    print("-" * 75)
    for row in history:
        print(
            f"{row['id']:<5}{row['target_ip']:<20}{row['timestamp']:<22}"
            f"{row['scan_duration']:.2f}s{'':<3}{row['open_port_count']}"
        )


def interactive_menu(args: argparse.Namespace) -> int:
    """Guided, prompt-driven flow for users who don't want to pass CLI flags."""
    db = get_db()
    while True:
        print("\n=== Netpreter: Network Security Assessment & Remediation Tool ===")
        print("1. Run Scan")
        print("2. View Past History")
        print("3. Launch Web Dashboard UI")
        print("4. Exit")

        choice = input("\nSelect an option [1-4]: ").strip()

        if choice == "1":
            _scan_submenu(args)
        elif choice == "2":
            _print_history(db)
        elif choice == "3":
            launch_web_dashboard(args.web_host, args.web_port, open_browser=not args.no_browser)
        elif choice == "4":
            print("[*] Exiting audit tool.")
            return 0
        else:
            print("[-] Invalid selection. Please choose an option from 1 to 4.")


def main(argv: List[str] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(levelname)s: %(message)s",
    )

    try:
        if args.web:
            return launch_web_dashboard(args.web_host, args.web_port, open_browser=not args.no_browser)
        if args.target:
            return run_scan(args.target, args.ports, args)
        return interactive_menu(args)
    except KeyboardInterrupt:
        print("\n\n[!] Audit aborted by user.")
        return 130


if __name__ == "__main__":
    sys.exit(main())
