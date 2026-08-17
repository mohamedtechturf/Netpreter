"""
Core scanning engine.

Handles target resolution/expansion, concurrent TCP connect-scanning, and
optional lightweight banner grabbing. Everything here relies solely on the
Python standard library so the tool has zero external dependencies.
"""

from __future__ import annotations

import concurrent.futures
import ipaddress
import logging
import socket
import time
from dataclasses import dataclass, field
from typing import Iterable, List, Optional, Sequence

logger = logging.getLogger("netpreter")

# Ports where sending nothing and just reading the server's greeting is
# enough to get a useful banner (no probe bytes are transmitted).
_PASSIVE_BANNER_PORTS = {21, 22, 23, 25, 110, 143, 3306}
_BANNER_READ_TIMEOUT = 1.0
_BANNER_MAX_BYTES = 256


@dataclass
class PortResult:
    """Outcome of probing a single port on a single host."""

    host: str
    port: int
    is_open: bool
    banner: Optional[str] = None


@dataclass
class HostReport:
    """Aggregated scan results for one target host."""

    host: str
    open_ports: List[PortResult] = field(default_factory=list)
    duration_seconds: float = 0.0
    ports_scanned: int = 0
    error: Optional[str] = None


class TargetResolutionError(ValueError):
    """Raised when a target host/IP/CIDR expression cannot be resolved."""


def resolve_targets(raw_target: str) -> List[str]:
    """
    Expand a user-supplied target expression into a list of IP addresses.

    Accepts:
      - A single hostname (resolved via DNS)
      - A single IPv4/IPv6 address
      - A CIDR network (e.g. 192.168.1.0/28) -- expanded to host addresses
      - A comma-separated combination of the above

    Raises TargetResolutionError with a human-readable reason on failure.
    """
    targets: List[str] = []
    for chunk in (part.strip() for part in raw_target.split(",")):
        if not chunk:
            continue

        if "/" in chunk:
            try:
                network = ipaddress.ip_network(chunk, strict=False)
            except ValueError as exc:
                raise TargetResolutionError(f"Invalid CIDR range '{chunk}': {exc}") from exc
            hosts = list(network.hosts()) or [network.network_address]
            if len(hosts) > 1024:
                raise TargetResolutionError(
                    f"Refusing to expand '{chunk}': {len(hosts)} addresses exceeds the "
                    "1024-host safety limit for a single audit run."
                )
            targets.extend(str(ip) for ip in hosts)
            continue

        try:
            ipaddress.ip_address(chunk)
            targets.append(chunk)
            continue
        except ValueError:
            pass

        try:
            resolved = socket.gethostbyname(chunk)
        except socket.gaierror as exc:
            raise TargetResolutionError(f"Unable to resolve hostname '{chunk}': {exc}") from exc
        targets.append(resolved)

    if not targets:
        raise TargetResolutionError("No valid targets were provided.")

    # Preserve order while de-duplicating.
    seen = set()
    deduped = []
    for t in targets:
        if t not in seen:
            seen.add(t)
            deduped.append(t)
    return deduped


def get_local_ip() -> str:
    """Best-effort discovery of the primary outbound local IP address."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        try:
            sock.connect(("8.8.8.8", 80))
            return sock.getsockname()[0]
        except OSError:
            return "127.0.0.1"


def _grab_banner(sock: socket.socket, port: int) -> Optional[str]:
    """
    Best-effort, read-only banner capture on an already-connected socket.

    Only reads what the remote service proactively sends (e.g. an SSH or
    FTP greeting). No payloads or protocol probes are transmitted, so this
    never sends anything an ordinary client connection wouldn't.
    """
    try:
        sock.settimeout(_BANNER_READ_TIMEOUT)
        data = sock.recv(_BANNER_MAX_BYTES)
        if not data:
            return None
        text = data.decode("utf-8", errors="replace").strip()
        return text.splitlines()[0][:120] if text else None
    except (socket.timeout, OSError):
        return None


def scan_port(host: str, port: int, timeout: float = 1.0, grab_banner: bool = True) -> PortResult:
    """Probe a single TCP port with a connect() handshake, optionally reading a banner."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            if sock.connect_ex((host, port)) != 0:
                return PortResult(host=host, port=port, is_open=False)

            banner = None
            if grab_banner and port in _PASSIVE_BANNER_PORTS:
                banner = _grab_banner(sock, port)
            return PortResult(host=host, port=port, is_open=True, banner=banner)
    except (socket.error, socket.timeout, OSError) as exc:
        logger.debug("Error probing %s:%s - %s", host, port, exc)
        return PortResult(host=host, port=port, is_open=False)


def scan_host(
    host: str,
    ports: Sequence[int],
    timeout: float = 1.0,
    max_threads: int = 100,
    grab_banner: bool = True,
    progress_callback=None,
) -> HostReport:
    """Concurrently scan a set of ports on a single host and return a HostReport."""
    start_time = time.time()
    open_ports: List[PortResult] = []
    completed = 0
    total = len(ports)

    max_workers = max(1, min(max_threads, total or 1))
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(scan_port, host, port, timeout, grab_banner): port
            for port in ports
        }
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            completed += 1
            if progress_callback:
                progress_callback(host, completed, total)
            if result.is_open:
                open_ports.append(result)

    open_ports.sort(key=lambda r: r.port)
    return HostReport(
        host=host,
        open_ports=open_ports,
        duration_seconds=time.time() - start_time,
        ports_scanned=total,
    )


def scan_targets(
    targets: Iterable[str],
    ports: Sequence[int],
    timeout: float = 1.0,
    max_threads: int = 100,
    grab_banner: bool = True,
    progress_callback=None,
) -> List[HostReport]:
    """Sequentially audit each target host (each host itself is scanned concurrently)."""
    reports = []
    for host in targets:
        reports.append(
            scan_host(
                host,
                ports,
                timeout=timeout,
                max_threads=max_threads,
                grab_banner=grab_banner,
                progress_callback=progress_callback,
            )
        )
    return reports
