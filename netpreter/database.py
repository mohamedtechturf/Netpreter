"""
Port risk database.

Maps well-known TCP ports to the service that conventionally runs there,
a qualitative risk severity, a plain-language description of *why* the
exposure matters, and concrete remediation guidance. This is reference
data for triage, not a substitute for vendor advisories or a full
authenticated configuration review.

Severity scale (highest to lowest): Critical, High, Medium, Low, Info.
"""

from typing import Dict, TypedDict


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

PORT_SECURITY_DATABASE: Dict[int, PortInfo] = {
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

# Convenience subsets for CLI port-selection shortcuts.
TOP_PORTS = sorted(PORT_SECURITY_DATABASE.keys())


def get_port_info(port: int) -> PortInfo:
    """Return risk metadata for a port, falling back to a generic entry."""
    return PORT_SECURITY_DATABASE.get(port, UNKNOWN_PORT_INFO)
