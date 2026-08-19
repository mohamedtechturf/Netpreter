"""
SQLite persistence layer for Netpreter.

Replaces the static `database.py` dictionary with a native, zero-dependency
SQLite database (`netpreter.db`). Handles:

  - `port_security`      : port -> risk/remediation reference data
                            (auto-seeded from the legacy curated dataset the
                            first time the database is created)
  - `scan_history`        : one row per completed audit run
  - `scan_results`        : one row per open port found during a run
  - `cve_vulnerabilities` : curated CVE cross-reference data, keyed by
                            service name

Only the Python standard library (`sqlite3`) is used. All connections are
opened per-operation via a context manager, which keeps the module safe to
call concurrently from multiple threads (e.g. the web dashboard's
background scan threads) without sharing a single sqlite3 connection object
across threads.
"""

from __future__ import annotations

import os
import sqlite3
import threading
import time
from contextlib import contextmanager
from typing import Any, Dict, List, Optional, Sequence, TypedDict

DB_FILENAME = "netpreter.db"

# Directory of the installed package -> repo root is one level up.
_PACKAGE_DIR = os.path.dirname(os.path.abspath(__file__))
_DEFAULT_DB_PATH = os.path.join(os.path.dirname(_PACKAGE_DIR), DB_FILENAME)


class PortInfo(TypedDict):
    service: str
    severity: str
    description: str
    remediation: str


SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info"]
SEVERITY_WEIGHT = {name: idx for idx, name in enumerate(SEVERITY_ORDER)}

UNKNOWN_PORT_INFO: PortInfo = {
    "service": "Unknown / Custom",
    "severity": "Info",
    "description": "Unrecognized service running on a non-standard port.",
    "remediation": (
        "Identify the running process (e.g. `ss -ltnp` / `lsof -i`), "
        "verify a legitimate business need, and restrict or close the "
        "port if it isn't required."
    ),
}

# ---------------------------------------------------------------------------
# Seed data. This is the same curated dataset that used to live in
# database.py; it now exists only as one-time seed data for a fresh
# `netpreter.db`, and the dictionary itself is never consulted again once
# the database has been created.
# ---------------------------------------------------------------------------
_SEED_PORT_SECURITY: Dict[int, PortInfo] = {
    21: {
        "service": "FTP",
        "severity": "Medium",
        "description": "FTP transmits credentials and data in cleartext.",
        "remediation": "Migrate to SFTP (SSH File Transfer Protocol) or FTPS (FTP over TLS). Disable anonymous login.",
    },
    22: {
        "service": "SSH",
        "severity": "Info",
        "description": "Secure Shell remote administration port is open.",
        "remediation": "Ensure password authentication is disabled in favor of Ed25519/RSA keys, disable root login (PermitRootLogin no), and keep OpenSSH updated.",
    },
    23: {
        "service": "Telnet",
        "severity": "Critical",
        "description": "Telnet transmits all communications, including passwords, unencrypted.",
        "remediation": "Immediately disable the Telnet daemon and replace it with SSH.",
    },
    25: {
        "service": "SMTP",
        "severity": "Low",
        "description": "Mail transfer service exposed.",
        "remediation": "Enforce STARTTLS, verify SPF/DKIM/DMARC records, and ensure the server is not an open relay.",
    },
    53: {
        "service": "DNS",
        "severity": "Low",
        "description": "DNS service is listening.",
        "remediation": "Disable open recursion if this is an authoritative-only server to prevent DNS amplification abuse.",
    },
    80: {
        "service": "HTTP",
        "severity": "Medium",
        "description": "Unencrypted HTTP web service.",
        "remediation": "Enforce HTTPS with TLS 1.2/1.3, obtain a valid certificate, and implement HTTP Strict Transport Security (HSTS) headers.",
    },
    110: {
        "service": "POP3",
        "severity": "Medium",
        "description": "Cleartext POP3 mail retrieval protocol.",
        "remediation": "Switch to POP3 over SSL/TLS (port 995) or modern OAuth2-secured IMAP.",
    },
    135: {
        "service": "MS-RPC",
        "severity": "High",
        "description": "Microsoft RPC endpoint mapper is exposed.",
        "remediation": "Block port 135 at the perimeter firewall; RPC should never be reachable from untrusted networks.",
    },
    139: {
        "service": "NetBIOS",
        "severity": "High",
        "description": "NetBIOS file sharing session service exposed.",
        "remediation": "Block NetBIOS ports at the perimeter firewall and disable NetBIOS over TCP/IP if not required.",
    },
    143: {
        "service": "IMAP",
        "severity": "Medium",
        "description": "Cleartext IMAP email protocol.",
        "remediation": "Enforce IMAPS (IMAP over TLS on port 993).",
    },
    161: {
        "service": "SNMP",
        "severity": "High",
        "description": "SNMP agent exposed; many deployments still use default 'public'/'private' community strings.",
        "remediation": "Restrict SNMP to management networks, switch to SNMPv3 with authentication and encryption, and change default community strings.",
    },
    389: {
        "service": "LDAP",
        "severity": "High",
        "description": "Directory service exposed without mandatory encryption.",
        "remediation": "Require LDAPS (port 636) or STARTTLS, and restrict access to authorized application and management subnets.",
    },
    443: {
        "service": "HTTPS",
        "severity": "Info",
        "description": "Encrypted web service.",
        "remediation": "Ensure legacy protocols (SSLv3, TLS 1.0, TLS 1.1) are disabled and strong cipher suites (AES-GCM, ChaCha20) are configured.",
    },
    445: {
        "service": "SMB",
        "severity": "Critical",
        "description": "Direct-hosted SMB file sharing is exposed.",
        "remediation": "Never expose SMB to public networks. Ensure SMBv1 is disabled completely, enable SMB signing/encryption, and isolate behind a VPN.",
    },
    636: {
        "service": "LDAPS",
        "severity": "Info",
        "description": "Encrypted LDAP directory service.",
        "remediation": "Confirm the certificate is valid and modern TLS versions/ciphers are enforced.",
    },
    993: {
        "service": "IMAPS",
        "severity": "Info",
        "description": "Encrypted IMAP mail retrieval.",
        "remediation": "Confirm the certificate is valid and legacy TLS versions are disabled.",
    },
    995: {
        "service": "POP3S",
        "severity": "Info",
        "description": "Encrypted POP3 mail retrieval.",
        "remediation": "Confirm the certificate is valid and legacy TLS versions are disabled.",
    },
    1433: {
        "service": "MSSQL",
        "severity": "High",
        "description": "Microsoft SQL Server database is directly accessible.",
        "remediation": "Restrict database access to application servers using firewall rules or place the database within an isolated private subnet.",
    },
    3306: {
        "service": "MySQL",
        "severity": "High",
        "description": "MySQL database port is open.",
        "remediation": "Bind MySQL to localhost (127.0.0.1) or an internal subnet. Require SSL/TLS for remote connections.",
    },
    3389: {
        "service": "RDP",
        "severity": "High",
        "description": "Remote Desktop Protocol (RDP) service is listening.",
        "remediation": "Do not expose RDP to the public internet. Require Network Level Authentication (NLA), enforce MFA, and place behind a VPN or RDP Gateway.",
    },
    5432: {
        "service": "PostgreSQL",
        "severity": "High",
        "description": "PostgreSQL database port is open.",
        "remediation": "Configure pg_hba.conf to allow connections only from authorized internal IP addresses and enforce SSL.",
    },
    5900: {
        "service": "VNC",
        "severity": "Critical",
        "description": "VNC remote-control service exposed; historically weak/optional authentication.",
        "remediation": "Never expose VNC directly to the internet. Tunnel over SSH/VPN and enforce strong authentication.",
    },
    6379: {
        "service": "Redis",
        "severity": "Critical",
        "description": "Redis in-memory store is accessible.",
        "remediation": "Redis has no encryption by default and is often unauthenticated. Bind to 127.0.0.1, enable strong authentication via requirepass, or use TLS.",
    },
    8080: {
        "service": "HTTP-Proxy / Alt-HTTP",
        "severity": "Low",
        "description": "Alternative HTTP port commonly used for development or management dashboards.",
        "remediation": "Ensure administrative consoles (e.g., Tomcat, Jenkins) are protected with strong authentication and TLS encryption.",
    },
    8443: {
        "service": "Alt-HTTPS",
        "severity": "Low",
        "description": "Alternative HTTPS port, often used for admin consoles or app servers.",
        "remediation": "Confirm the certificate is valid, TLS is properly configured, and admin interfaces require strong authentication.",
    },
    9200: {
        "service": "Elasticsearch",
        "severity": "Critical",
        "description": "Elasticsearch REST API exposed; historically ships without authentication.",
        "remediation": "Enable security features (authentication/TLS), bind to internal interfaces only, and never expose to the public internet.",
    },
    11211: {
        "service": "Memcached",
        "severity": "Critical",
        "description": "Memcached exposed; unauthenticated by default and abusable for UDP amplification.",
        "remediation": "Bind to localhost/internal interfaces only, disable the UDP listener, and firewall the port from the internet.",
    },
    27017: {
        "service": "MongoDB",
        "severity": "Critical",
        "description": "MongoDB NoSQL database port is open.",
        "remediation": "Enable authentication (authorization: enabled), bind to local interfaces, and encrypt traffic using TLS.",
    },
}

# Small curated CVE cross-reference sample, keyed by the same service names
# used in `port_security`. This is illustrative reference data for triage,
# not a live feed -- there is no network fetching involved.
_SEED_CVE_DATA = [
    ("Telnet", "CVE-1999-0619", 5.0, "Telnet transmits authentication credentials in cleartext, allowing trivial interception."),
    ("FTP", "CVE-1999-0497", 5.0, "Anonymous FTP access can expose sensitive files if not properly restricted."),
    ("SMB", "CVE-2017-0144", 8.1, "EternalBlue: SMBv1 remote code execution via crafted packets (WannaCry/NotPetya vector)."),
    ("SMB", "CVE-2020-0796", 10.0, "SMBGhost: SMBv3 compression remote code execution vulnerability."),
    ("RDP", "CVE-2019-0708", 9.8, "BlueKeep: pre-authentication remote code execution in Remote Desktop Services."),
    ("Redis", "CVE-2022-0543", 10.0, "Lua sandbox escape in Redis leading to remote code execution on Debian-based builds."),
    ("MongoDB", "CVE-2021-20329", 5.9, "Improper input validation allowing NoSQL injection in some driver/server combinations."),
    ("Elasticsearch", "CVE-2015-1427", 9.8, "Groovy scripting engine sandbox bypass allowing remote code execution."),
    ("Memcached", "CVE-2018-1000115", 7.5, "Integer overflow in Memcached allowing remote code execution via crafted requests."),
    ("VNC", "CVE-2019-15681", 9.8, "Heap-based buffer overflow in some VNC server implementations allowing remote code execution."),
    ("MySQL", "CVE-2021-2154", 4.9, "Server component vulnerability allowing unauthorized data access/denial of service."),
    ("PostgreSQL", "CVE-2019-10164", 8.1, "Stack-based buffer overflow via crafted authentication packets."),
    ("LDAP", "CVE-2020-1472", 10.0, "Zerologon: Netlogon elevation of privilege that can cascade into directory compromise."),
    ("SNMP", "CVE-1999-0517", 5.0, "Default/guessable SNMP community strings allow unauthorized read/write access."),
]


@contextmanager
def _connect(db_path: str):
    """Open a short-lived, thread-local sqlite3 connection as a context manager."""
    conn = sqlite3.connect(db_path, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


class Database:
    """
    Thin, thread-safe SQLite manager for Netpreter.

    A new sqlite3 connection is opened for every operation (sqlite3
    connections are not safe to share across threads), guarded by a
    process-wide lock for writes so concurrent scan threads never race on
    the same database file.
    """

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or _DEFAULT_DB_PATH
        self._write_lock = threading.Lock()
        self._initialize()

    # -- schema / seeding ---------------------------------------------

    def _initialize(self) -> None:
        is_new = not os.path.exists(self.db_path)
        with self._write_lock, _connect(self.db_path) as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS port_security (
                    port        INTEGER PRIMARY KEY,
                    service     TEXT NOT NULL,
                    severity    TEXT NOT NULL,
                    description TEXT NOT NULL,
                    remediation TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS scan_history (
                    id            INTEGER PRIMARY KEY AUTOINCREMENT,
                    target_ip     TEXT NOT NULL,
                    timestamp     DATETIME DEFAULT CURRENT_TIMESTAMP,
                    scan_duration REAL
                );

                CREATE TABLE IF NOT EXISTS scan_results (
                    id      INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER NOT NULL REFERENCES scan_history(id) ON DELETE CASCADE,
                    port    INTEGER NOT NULL,
                    state   TEXT NOT NULL,
                    banner  TEXT
                );

                CREATE TABLE IF NOT EXISTS cve_vulnerabilities (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    service     TEXT NOT NULL,
                    cve_id      TEXT NOT NULL,
                    cvss_score  REAL,
                    summary     TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_scan_results_scan_id
                    ON scan_results(scan_id);
                CREATE INDEX IF NOT EXISTS idx_scan_history_timestamp
                    ON scan_history(timestamp);
                CREATE INDEX IF NOT EXISTS idx_cve_service
                    ON cve_vulnerabilities(service);
                """
            )

            if is_new or self._is_empty(conn, "port_security"):
                conn.executemany(
                    "INSERT OR IGNORE INTO port_security "
                    "(port, service, severity, description, remediation) "
                    "VALUES (?, ?, ?, ?, ?)",
                    [
                        (port, info["service"], info["severity"], info["description"], info["remediation"])
                        for port, info in _SEED_PORT_SECURITY.items()
                    ],
                )

            if is_new or self._is_empty(conn, "cve_vulnerabilities"):
                conn.executemany(
                    "INSERT INTO cve_vulnerabilities (service, cve_id, cvss_score, summary) "
                    "VALUES (?, ?, ?, ?)",
                    _SEED_CVE_DATA,
                )

    @staticmethod
    def _is_empty(conn: sqlite3.Connection, table: str) -> bool:
        cur = conn.execute(f"SELECT COUNT(*) FROM {table}")  # noqa: S608 (fixed table names only)
        return cur.fetchone()[0] == 0

    # -- port_security ---------------------------------------------------

    def get_port_info(self, port: int) -> PortInfo:
        """Return risk metadata for a port, falling back to a generic entry."""
        with _connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT service, severity, description, remediation "
                "FROM port_security WHERE port = ?",
                (port,),
            ).fetchone()
        if row is None:
            return dict(UNKNOWN_PORT_INFO)
        return {
            "service": row["service"],
            "severity": row["severity"],
            "description": row["description"],
            "remediation": row["remediation"],
        }

    def get_top_ports(self) -> List[int]:
        """All ports present in the curated risk database, sorted ascending."""
        with _connect(self.db_path) as conn:
            rows = conn.execute("SELECT port FROM port_security ORDER BY port ASC").fetchall()
        return [row["port"] for row in rows]

    # -- CVE cross-reference ---------------------------------------------

    def get_cves_for_service(self, service: str) -> List[Dict[str, Any]]:
        with _connect(self.db_path) as conn:
            rows = conn.execute(
                "SELECT cve_id, cvss_score, summary FROM cve_vulnerabilities "
                "WHERE service = ? ORDER BY cvss_score DESC",
                (service,),
            ).fetchall()
        return [dict(row) for row in rows]

    # -- scan_history / scan_results --------------------------------------

    def record_scan(
        self,
        target_ip: str,
        duration_seconds: float,
        open_ports: Sequence[Any],
    ) -> int:
        """
        Persist one completed scan run and its open-port findings.

        `open_ports` items only need `.port` and optionally `.banner`
        attributes (a scanner.PortResult satisfies this duck-typed shape).
        Returns the new scan_history row id.
        """
        with self._write_lock, _connect(self.db_path) as conn:
            cur = conn.execute(
                "INSERT INTO scan_history (target_ip, scan_duration) VALUES (?, ?)",
                (target_ip, duration_seconds),
            )
            scan_id = cur.lastrowid
            conn.executemany(
                "INSERT INTO scan_results (scan_id, port, state, banner) VALUES (?, ?, ?, ?)",
                [
                    (scan_id, result.port, "Open", getattr(result, "banner", None))
                    for result in open_ports
                ],
            )
        return scan_id

    def get_scan_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        with _connect(self.db_path) as conn:
            rows = conn.execute(
                """
                SELECT sh.id, sh.target_ip, sh.timestamp, sh.scan_duration,
                       COUNT(sr.id) AS open_port_count
                FROM scan_history sh
                LEFT JOIN scan_results sr ON sr.scan_id = sh.id
                GROUP BY sh.id
                ORDER BY sh.timestamp DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def get_scan_detail(self, scan_id: int) -> Optional[Dict[str, Any]]:
        with _connect(self.db_path) as conn:
            scan_row = conn.execute(
                "SELECT id, target_ip, timestamp, scan_duration FROM scan_history WHERE id = ?",
                (scan_id,),
            ).fetchone()
            if scan_row is None:
                return None
            result_rows = conn.execute(
                "SELECT port, state, banner FROM scan_results WHERE scan_id = ? ORDER BY port ASC",
                (scan_id,),
            ).fetchall()

        findings = []
        for r in result_rows:
            info = self.get_port_info(r["port"])
            findings.append(
                {
                    "port": r["port"],
                    "state": r["state"],
                    "banner": r["banner"],
                    "service": info["service"],
                    "severity": info["severity"],
                    "description": info["description"],
                    "remediation": info["remediation"],
                    "cves": self.get_cves_for_service(info["service"]),
                }
            )

        return {
            "id": scan_row["id"],
            "target_ip": scan_row["target_ip"],
            "timestamp": scan_row["timestamp"],
            "scan_duration": scan_row["scan_duration"],
            "findings": findings,
        }

    # -- aggregate stats ---------------------------------------------------

    def get_stats(self) -> Dict[str, Any]:
        with _connect(self.db_path) as conn:
            total_scans = conn.execute("SELECT COUNT(*) FROM scan_history").fetchone()[0]

            severity_rows = conn.execute(
                """
                SELECT ps.severity AS severity, COUNT(*) AS n
                FROM scan_results sr
                JOIN port_security ps ON ps.port = sr.port
                GROUP BY ps.severity
                """
            ).fetchall()
            severity_distribution = {sev: 0 for sev in SEVERITY_ORDER}
            for row in severity_rows:
                severity_distribution[row["severity"]] = row["n"]

            top_ports_rows = conn.execute(
                """
                SELECT sr.port AS port, COUNT(*) AS n
                FROM scan_results sr
                GROUP BY sr.port
                ORDER BY n DESC
                LIMIT 10
                """
            ).fetchall()

            recent_rows = conn.execute(
                """
                SELECT sh.id, sh.target_ip, sh.timestamp, COUNT(sr.id) AS open_port_count
                FROM scan_history sh
                LEFT JOIN scan_results sr ON sr.scan_id = sh.id
                GROUP BY sh.id
                ORDER BY sh.timestamp DESC
                LIMIT 20
                """
            ).fetchall()

        top_ports = []
        for row in top_ports_rows:
            info = self.get_port_info(row["port"])
            top_ports.append({"port": row["port"], "service": info["service"], "count": row["n"]})

        return {
            "total_scans": total_scans,
            "severity_distribution": severity_distribution,
            "top_ports": top_ports,
            "recent_scans": [dict(r) for r in recent_rows],
        }


# ---------------------------------------------------------------------------
# Process-wide singleton. All callers (CLI, report renderer, web server) share
# one Database instance pointed at the same netpreter.db file, but each
# operation still opens/closes its own sqlite3 connection under the hood.
# ---------------------------------------------------------------------------
_db_instance: Optional[Database] = None
_db_instance_lock = threading.Lock()


def get_db(db_path: Optional[str] = None) -> Database:
    """Return the shared Database singleton, creating it on first use."""
    global _db_instance
    with _db_instance_lock:
        if _db_instance is None:
            _db_instance = Database(db_path)
        return _db_instance
