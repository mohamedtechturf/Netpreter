#!/usr/bin/env python3
"""
Network Security & Configuration Audit Tool
-------------------------------------------
This tool scans target endpoints for open ports, identifies common
misconfigurations and risky legacy protocols, and outputs structured 
remediation recommendations.
"""

import concurrent.futures
import ipaddress
import os
import socket
import sys
import time

PORT_SECURITY_DATABASE = {
    21: {
        "service": "FTP",
        "severity": "Medium",
        "description": "FTP transmits credentials and data in cleartext.",
        "remediation": "Migrate to SFTP (SSH File Transfer Protocol) or FTPS (FTP over TLS). Disable anonymous login."
    },
    22: {
        "service": "SSH",
        "severity": "Info",
        "description": "Secure Shell remote administration port is open.",
        "remediation": "Ensure password authentication is disabled in favor of Ed25519/RSA keys, disable root login (PermitRootLogin no), and keep OpenSSH updated."
    },
    23: {
        "service": "Telnet",
        "severity": "Critical",
        "description": "Telnet transmits all communications, including passwords, unencrypted.",
        "remediation": "Immediately disable the Telnet daemon and replace it with SSH."
    },
    25: {
        "service": "SMTP",
        "severity": "Low",
        "description": "Mail transfer service exposed.",
        "remediation": "Enforce STARTTLS, verify SPF/DKIM/DMARC records, and ensure the server is not an open relay."
    },
    53: {
        "service": "DNS",
        "severity": "Low",
        "description": "DNS service is listening.",
        "remediation": "Disable open recursion if this is an authoritative-only server to prevent DNS amplification attacks."
    },
    80: {
        "service": "HTTP",
        "severity": "Medium",
        "description": "Unencrypted HTTP web service.",
        "remediation": "Enforce HTTPS with TLS 1.2/1.3, obtain a valid certificate, and implement HTTP Strict Transport Security (HSTS) headers."
    },
    110: {
        "service": "POP3",
        "severity": "Medium",
        "description": "Cleartext POP3 mail retrieval protocol.",
        "remediation": "Switch to POP3 over SSL/TLS (port 995) or modern OAuth2-secured IMAP."
    },
    139: {
        "service": "NetBIOS",
        "severity": "High",
        "description": "NetBIOS file sharing exposed.",
        "remediation": "Block NetBIOS ports at the perimeter firewall and disable NetBIOS over TCP/IP if not required."
    },
    143: {
        "service": "IMAP",
        "severity": "Medium",
        "description": "Cleartext IMAP email protocol.",
        "remediation": "Enforce IMAPS (IMAP over TLS on port 993)."
    },
    443: {
        "service": "HTTPS",
        "severity": "Info",
        "description": "Encrypted web service.",
        "remediation": "Ensure legacy protocols (SSLv3, TLS 1.0, TLS 1.1) are disabled and strong cipher suites (AES-GCM, ChaCha20) are configured."
    },
    445: {
        "service": "SMB",
        "severity": "Critical",
        "description": "Direct-hosted SMB file sharing is exposed.",
        "remediation": "Never expose SMB to public networks. Ensure SMBv1 is disabled completely, enable SMB signing/encryption, and isolate behind a VPN."
    },
    1433: {
        "service": "MSSQL",
        "severity": "High",
        "description": "Microsoft SQL Server database is directly accessible.",
        "remediation": "Restrict database access to application servers using firewall rules or place the database within an isolated private VPC."
    },
    3306: {
        "service": "MySQL",
        "severity": "High",
        "description": "MySQL database port is open.",
        "remediation": "Bind MySQL to localhost (127.0.0.1) or an internal subnet. Require SSL connections for remote access."
    },
    3389: {
        "service": "RDP",
        "severity": "High",
        "description": "Remote Desktop Protocol (RDP) service is listening.",
        "remediation": "Do not expose RDP to the public internet. Require Network Level Authentication (NLA), use Multi-Factor Authentication (MFA), and place behind a VPN or RDP Gateway."
    },
    5432: {
        "service": "PostgreSQL",
        "severity": "High",
        "description": "PostgreSQL database port is open.",
        "remediation": "Configure pg_hba.conf to allow connections only from authorized internal IP addresses and enforce SSL."
    },
    6379: {
        "service": "Redis",
        "severity": "Critical",
        "description": "Redis in-memory store is accessible.",
        "remediation": "Redis has no encryption by default and is often unauthenticated. Bind to 127.0.0.1, enable strong authentication via requirepass, or use TLS."
    },
    8080: {
        "service": "HTTP-Proxy / Alt-HTTP",
        "severity": "Low",
        "description": "Alternative HTTP port commonly used for development or management dashboards.",
        "remediation": "Ensure administrative consoles (e.g., Tomcat, Jenkins) are protected with strong authentication and TLS encryption."
    },
    27017: {
        "service": "MongoDB",
        "severity": "Critical",
        "description": "MongoDB NoSQL database port is open.",
        "remediation": "Enable authentication (auth=true), bind to local interfaces, and encrypt traffic using TLS."
    }
}


def get_local_ip():
    """Retrieves the local IP address of the scanning host."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
    except Exception:
        local_ip = "127.0.0.1"
    finally:
        s.close()
    return local_ip


def scan_port(host, port, timeout=1.0):
    """Attempts a TCP handshake with the target port."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            if result == 0:
                return port
    except (socket.error, socket.timeout):
        pass
    return None


def save_log(target_host, report_content):
    """Saves the scan report output to a timestamped file in the logs directory."""
    os.makedirs("logs", exist_ok=True)
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    sanitized_host = target_host.replace(".", "_").replace(":", "_")
    filename = f"logs/audit_{sanitized_host}_{timestamp}.log"
    
    with open(filename, "w", encoding="utf-8") as log_file:
        log_file.write(report_content)
    
    print(f"[*] Report successfully logged to: {filename}")


def run_audit(target_host, ports_to_scan, max_threads=50):
    """Executes multi-threaded port scanning and compiles audit findings."""
    print(f"\n[*] Initiating security audit on target: {target_host}")
    print(f"[*] Total ports queued: {len(ports_to_scan)}")
    print("[*] Analysis in progress...\n")

    start_time = time.time()
    open_ports = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
        future_to_port = {
            executor.submit(scan_port, target_host, port): port 
            for port in ports_to_scan
        }
        for future in concurrent.futures.as_completed(future_to_port):
            result = future.result()
            if result:
                open_ports.append(result)

    open_ports.sort()
    duration = time.time() - start_time
    
    display_report(target_host, open_ports, duration)


def display_report(target_host, open_ports, duration):
    """Formats, prints, and logs the security posture and remediation report."""
    report_lines = []
    
    def log_line(line=""):
        print(line)
        report_lines.append(line)

    log_line("=" * 80)
    log_line(f" SECURITY AUDIT REPORT: {target_host}")
    log_line(f" Completed in: {duration:.2f} seconds | Open Ports Detected: {len(open_ports)}")
    log_line("=" * 80)

    if not open_ports:
        log_line("[+] No open ports detected from the scan list. Perimeter posture appears restrictive.")
        log_line("=" * 80)
        save_log(target_host, "\n".join(report_lines))
        return

    findings_count = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}

    for port in open_ports:
        info = PORT_SECURITY_DATABASE.get(port, {
            "service": "Unknown / Custom",
            "severity": "Info",
            "description": "Unrecognized service running on non-standard port.",
            "remediation": "Identify the running process, verify business need, and restrict access if unnecessary."
        })

        severity = info["severity"]
        findings_count[severity] = findings_count.get(severity, 0) + 1

        log_line(f"\n[!] Port {port}/TCP: {info['service']}")
        log_line(f"    Severity:    [{severity.upper()}]")
        log_line(f"    Observation: {info['description']}")
        log_line(f"    Remediation: {info['remediation']}")

    log_line("\n" + "-" * 80)
    log_line(" SUMMARY OF FINDINGS:")
    for sev, count in findings_count.items():
        if count > 0:
            log_line(f"  - {sev}: {count}")
    log_line("-" * 80)
    log_line(" NEXT STEPS:")
    log_line("  1. Apply firewall rules (iptables/UFW/Network Security Groups) to close unused ports.")
    log_line("  2. Update any legacy or plaintext protocols to secure, encrypted alternatives.")
    log_line("  3. Run authenticated configuration audits on internal services.")
    log_line("=" * 80 + "\n")

    save_log(target_host, "\n".join(report_lines))


def menu():
    """CLI Menu for selecting scan targets."""
    ports = list(PORT_SECURITY_DATABASE.keys())

    while True:
        print("\n=== Network Security Assessment & Remediation Tool ===")
        print("1. Scan Local Host (127.0.0.1)")
        print("2. Scan Local Network Interface IP")
        print("3. Scan Custom IP / Hostname (Internal or External)")
        print("4. Exit")
        
        choice = input("\nSelect an option [1-4]: ").strip()

        if choice == "1":
            run_audit("127.0.0.1", ports)
        elif choice == "2":
            local_ip = get_local_ip()
            print(f"[*] Detected local interface IP: {local_ip}")
            run_audit(local_ip, ports)
        elif choice == "3":
            target = input("Enter target IP address or hostname: ").strip()
            if not target:
                print("[-] Target cannot be empty.")
                continue
            try:
                resolved_ip = socket.gethostbyname(target)
                print(f"[*] Target resolved to: {resolved_ip}")
                run_audit(resolved_ip, ports)
            except socket.gaierror:
                print(f"[-] Error: Unable to resolve hostname '{target}'.")
        elif choice == "4":
            print("[*] Exiting audit tool.")
            sys.exit(0)
        else:
            print("[-] Invalid selection. Please choose an option from 1 to 4.")


if __name__ == "__main__":
    try:
        menu()
    except KeyboardInterrupt:
        print("\n\n[!] Audit aborted by user.")
        sys.exit(0)