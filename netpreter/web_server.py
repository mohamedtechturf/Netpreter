"""
local Web Dashboard server for Netpreter.

Built entirely on the standard library (`http.server`, `json`, `threading`,
`urllib.parse`). Serves the single-file dashboard at `templates/index.html`
and a small JSON API that the dashboard's JavaScript polls/POSTs to.

Endpoints
---------
GET  /                     -> templates/index.html
GET  /api/scans            -> recent scan_history rows (JSON list)
GET  /api/scans/<id>       -> open ports + remediation + CVEs for one scan
GET  /api/stats            -> aggregated severity/port/scan stats
POST /api/scan             -> {"target": "...", "ports": "top"|"22,80"|"1-1024",
                                "timeout": 1.0, "threads": 100, "banner": true}
                               Starts a scan in a background thread and
                               returns immediately with a queued status.
GET  /api/scan/<queue_id>  -> poll status of a queued scan started via POST
                               /api/scan ("running" | "done" | "error", plus
                               the resulting scan_id once done)
"""

from __future__ import annotations

import json
import logging
import os
import re
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from . import __version__
from .db import get_db
from .scanner import TargetResolutionError, resolve_targets, scan_targets

logger = logging.getLogger("netpreter")

_PACKAGE_DIR = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.dirname(_PACKAGE_DIR)
_TEMPLATES_DIR = os.path.join(_REPO_ROOT, "templates")
_STATIC_DIR = os.path.join(_REPO_ROOT, "static")
_INDEX_HTML_PATH = os.path.join(_TEMPLATES_DIR, "index.html")

# Static assets served alongside the dashboard. Maps the URL path the
# frontend requests to (file-on-disk, content-type).
_STATIC_ASSETS = {
    "/styles.css": (os.path.join(_TEMPLATES_DIR, "styles.css"), "text/css; charset=utf-8"),
    "/scripts.js": (os.path.join(_TEMPLATES_DIR, "scripts.js"), "application/javascript; charset=utf-8"),
    "/static/np.ico": (os.path.join(_STATIC_DIR, "np.ico"), "image/x-icon"),
    "/static/chart.umd.min.js": (os.path.join(_STATIC_DIR, "chart.umd.min.js"), "application/javascript; charset=utf-8"),
}

_SCAN_ID_RE = re.compile(r"^/api/scans/(\d+)$")
_QUEUE_ID_RE = re.compile(r"^/api/scan/([0-9a-fA-F-]+)$")

# In-memory registry of background scan jobs started via POST /api/scan.
# Keyed by a queue_id (uuid4 string) so the frontend can poll for completion.
_jobs_lock = threading.Lock()
_jobs: dict = {}


def _parse_port_spec(spec: str):
    """Same parsing rules as the CLI's parse_port_spec, duplicated locally
    to avoid importing argparse-specific error types into the web layer."""
    spec = (spec or "top").strip().lower()
    if spec in ("top", "default", ""):
        return list(get_db().get_top_ports())

    ports = set()
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            start_s, _, end_s = chunk.partition("-")
            start, end = int(start_s), int(end_s)
            if not (0 < start <= end <= 65535):
                raise ValueError(f"Port range '{chunk}' out of bounds (1-65535)")
            ports.update(range(start, end + 1))
        else:
            port = int(chunk)
            if not (0 < port <= 65535):
                raise ValueError(f"Port '{chunk}' out of bounds (1-65535)")
            ports.add(port)

    if not ports:
        raise ValueError("No valid ports parsed from specification.")
    return sorted(ports)


def _run_scan_job(queue_id: str, target: str, ports, timeout: float, threads: int, grab_banner: bool) -> None:
    with _jobs_lock:
        _jobs[queue_id]["status"] = "running"
    try:
        targets = resolve_targets(target)
        db = get_db()
        scan_ids = []
        for reports in [scan_targets(targets, ports, timeout=timeout, max_threads=threads, grab_banner=grab_banner)]:
            for report in reports:
                if report.error:
                    continue
                scan_id = db.record_scan(report.host, report.duration_seconds, report.open_ports)
                scan_ids.append(scan_id)
        with _jobs_lock:
            _jobs[queue_id].update(status="done", scan_ids=scan_ids)
    except TargetResolutionError as exc:
        with _jobs_lock:
            _jobs[queue_id].update(status="error", error=str(exc))
    except Exception as exc:  # pragma: no cover - defensive catch-all for background thread
        logger.exception("Background scan job %s failed", queue_id)
        with _jobs_lock:
            _jobs[queue_id].update(status="error", error=str(exc))


class NetpreterRequestHandler(BaseHTTPRequestHandler):
    server_version = f"Netpreter/{__version__}"

    # Quiet down default request logging; keep it minimal and consistent
    # with the rest of the tool's console output.
    def log_message(self, fmt, *fmt_args):  # noqa: A002 - stdlib signature
        logger.debug("%s - %s", self.address_string(), fmt % fmt_args)

    # -- helpers -----------------------------------------------------------

    def _send_json(self, payload, status: int = 200) -> None:
        body = json.dumps(payload, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_error_json(self, message: str, status: int = 400) -> None:
        self._send_json({"error": message}, status=status)

    def _send_file(self, path: str, content_type: str) -> None:
        try:
            with open(path, "rb") as fh:
                body = fh.read()
        except OSError:
            self._send_error_json(f"Not found: {os.path.basename(path)}", status=404)
            return
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json_body(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length == 0:
            return {}
        raw = self.rfile.read(length)
        try:
            return json.loads(raw.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ValueError(f"Invalid JSON body: {exc}") from exc

    # -- routing -------------------------------------------------------------

    def do_GET(self) -> None:  # noqa: N802 - stdlib method name
        parsed = urlparse(self.path)
        path = parsed.path

        if path in ("/", "/index.html"):
            self._send_file(_INDEX_HTML_PATH, "text/html; charset=utf-8")
            return

        if path in _STATIC_ASSETS:
            file_path, content_type = _STATIC_ASSETS[path]
            self._send_file(file_path, content_type)
            return

        if path == "/api/stats":
            self._send_json(get_db().get_stats())
            return

        if path == "/api/scans":
            qs = parse_qs(parsed.query)
            limit = int(qs.get("limit", ["50"])[0])
            self._send_json(get_db().get_scan_history(limit=limit))
            return

        match = _SCAN_ID_RE.match(path)
        if match:
            scan_id = int(match.group(1))
            detail = get_db().get_scan_detail(scan_id)
            if detail is None:
                self._send_error_json(f"Scan {scan_id} not found", status=404)
            else:
                self._send_json(detail)
            return

        queue_match = _QUEUE_ID_RE.match(path)
        if queue_match:
            queue_id = queue_match.group(1)
            with _jobs_lock:
                job = _jobs.get(queue_id)
            if job is None:
                self._send_error_json(f"Unknown job id {queue_id}", status=404)
            else:
                self._send_json(job)
            return

        self._send_error_json(f"Not found: {path}", status=404)

    def do_POST(self) -> None:  # noqa: N802 - stdlib method name
        parsed = urlparse(self.path)

        if parsed.path != "/api/scan":
            self._send_error_json(f"Not found: {parsed.path}", status=404)
            return

        try:
            payload = self._read_json_body()
        except ValueError as exc:
            self._send_error_json(str(exc), status=400)
            return

        target = (payload.get("target") or "").strip()
        if not target:
            self._send_error_json("Missing required field 'target'.", status=400)
            return

        try:
            ports = _parse_port_spec(str(payload.get("ports", "top")))
        except ValueError as exc:
            self._send_error_json(str(exc), status=400)
            return

        timeout = float(payload.get("timeout", 1.0))
        threads = int(payload.get("threads", 100))
        grab_banner = bool(payload.get("banner", True))

        # Validate target resolution synchronously so obvious errors (bad
        # hostname, malformed CIDR) surface immediately instead of only
        # showing up when the client polls the job status.
        try:
            resolve_targets(target)
        except TargetResolutionError as exc:
            self._send_error_json(str(exc), status=400)
            return

        queue_id = str(uuid.uuid4())
        with _jobs_lock:
            _jobs[queue_id] = {"status": "queued", "target": target, "queued_at": time.time()}

        thread = threading.Thread(
            target=_run_scan_job,
            args=(queue_id, target, ports, timeout, threads, grab_banner),
            daemon=True,
        )
        thread.start()

        self._send_json({"queue_id": queue_id, "status": "queued"}, status=202)


def serve_forever(host: str = "127.0.0.1", port: int = 5000) -> None:
    """Start the Netpreter web dashboard and block until interrupted."""
    # Ensure the DB (and thus port_security/cve seed data) exists before the
    # dashboard starts serving requests.
    get_db()
    server = ThreadingHTTPServer((host, port), NetpreterRequestHandler)
    try:
        server.serve_forever()
    finally:
        server.server_close()
