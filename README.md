<a href="https://github.com/mohamedtechturf/Netpreter">
  <img alt="Netpreter" src="https://github.com/user-attachments/assets/4c672463-26f5-4b66-845d-9b4b219f46e0" width="100%">
</a>

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
![Linux](https://img.shields.io/badge/Supports-Linux-orange.svg)
![macOS](https://img.shields.io/badge/Supports-macOS-white.svg)
![windows](https://img.shields.io/badge/Supports-Windows-blue.svg)
[![github](https://img.shields.io/badge/github-repo-white?logo=github)](https://github.com/mohamedtechturf/Netpreter)
![Python](https://img.shields.io/badge/python-3.x-blue?logo=python)

# Netpreter — Network Security & Configuration Audit Tool

A lightweight, multi-threaded Python utility for perimeter security audits
of hosts and small network ranges. It
checks for commonly-exposed, high-risk TCP services, correlates results
against a curated risk database, optionally captures passive service
banners, and produces ranked, actionable remediation reports — from the
command line or from a local browser dashboard.


## Features

- **Multi-threaded TCP scanning** via `concurrent.futures`, with a
  per-host live progress bar.
- **Curated risk database** mapping 25+ common ports (SSH, RDP, SMB,
  Redis, MongoDB, Elasticsearch, etc.) to severity, plain-language
  impact, and specific remediation steps — plus a curated CVE
  cross-reference — persisted in a local SQLite database (`netpreter.db`).
- **Multiple targets per run** — single host, comma-separated list, or a
  CIDR range (e.g. `10.0.0.0/28`), expanded and de-duplicated
  automatically, with a safety cap to prevent accidental huge scans.
- **Flexible port selection** — the curated `top` list, explicit
  comma-separated ports, numeric ranges (`1-1024`), or any mix of these.
- **banner capture** — reads the greeting a
  service offers on connect, for extra triage context.
- **Multi-format reporting** — human-readable text, structured JSON, or
  CSV, printed to the console and saved to a timestamped file.
- **Persistent scan history** — every run is logged to SQLite
  (`scan_history` / `scan_results`), queryable from the CLI or the web API.
- **Three execution modes** — a scriptable quick-command CLI, a guided
  interactive terminal menu, or a local browser dashboard.
- **Zero external dependencies** — Python standard library only, for the
  scan engine, the database layer, and the web server alike. (The
  dashboard's charts load Chart.js from a CDN in the browser; nothing is
  `pip install`ed.)

## Prerequisites

- **Python:** Version 3.x or higher is required.
- **Terminal:** Access to a command-line interface (e.g., VS Code, terminal).

## Installation & Setup

1.  **Clone:** `git clone https://github.com/mohamedtechturf/Netpreter`
2.  **Navigate:** `cd Netpreter`
4.  **Execute:** Run `python netpreter.py` and enter the target hostname, IP address, or CIDR range when prompted.

## Usage

Netpreter has three ways to run — pick whichever fits the moment.

### 1. Quick Command CLI (scriptable / CI-friendly)

```bash
# Audit a single host against the curated risk-port list
python netpreter.py 192.168.1.10

# Audit multiple hosts and a small subnet, custom ports, JSON output
python netpreter.py "10.0.0.5,10.0.0.6,10.0.0.0/29" -p 22,80,443,1-1024 -f json

# Faster/slower scanning
python netpreter.py example.com -t 0.5 -T 200      # 0.5s timeout, 200 threads
python netpreter.py example.com --no-banner        # skip banner capture
python netpreter.py example.com --no-save          # print only, don't write a log
```

Run `python netpreter.py --help` for the full flag reference.

### 2. Interactive Menu CLI

Run with no arguments for a guided, prompt-driven flow:

```bash
python netpreter.py
```

```
=== Netpreter: Network Security Assessment & Remediation Tool ===
1. Run Scan
2. View Past History
3. Launch Web Dashboard UI
4. Exit
```

### 3. Web Dashboard UI

Starts a local server and opens a browser tab with charts, scan history, and a
searchable findings table:

```bash
python netpreter.py --web
# -> serves http://127.0.0.1:5000/ and opens it in your default browser

python netpreter.py --web --web-port 8000 --no-browser  # customize host/port, skip auto-open
```

## Project layout

```
Netpreter/
├── netpreter.py              # CLI entry point (all 3 execution modes)
├── netpreter/
│   ├── __init__.py           # package metadata/version
│   ├── db.py                 # SQLite persistence layer (schema, seeding, queries)
│   ├── scanner.py            # target resolution + concurrent scan engine
│   ├── report.py             # text/JSON/CSV report rendering & export
│   ├── cli.py                 # argument parsing + interactive menu + mode dispatch
│   └── web_server.py         # stdlib http.server-based dashboard + JSON API
├── templates/
│   └── index.html            # single-file dashboard (HTML/CSS/JS, Chart.js via CDN)
├── netpreter.db               # created at runtime — SQLite database
└── logs/                      # timestamped audit reports (created at runtime)
```

## How it works

1. **Resolve targets** — hostnames are DNS-resolved, IPs are validated,
   CIDR ranges are expanded to individual host addresses (capped at 1024
   hosts per run as a safety limit).
2. **Scan** — each requested port is probed with a standard TCP
   connect() handshake via a thread pool; a closed/filtered port is
   simply skipped.
3. **Classify** — every open port is looked up in the SQLite-backed risk
   database and tagged `Critical` / `High` / `Medium` / `Low` / `Info`;
   ports outside the database still show up as unrecognized findings.
   Findings are also cross-referenced against a curated CVE table.
4. **Persist** — every completed run (target, duration, and any open
   ports/banners) is written to `scan_history` / `scan_results` in
   `netpreter.db`, whether the run came from the CLI or the web dashboard.
5. **Report** — findings are sorted by severity, summarized per host and
   overall, and rendered to text, JSON, or CSV — or browsed interactively
   in the web dashboard's charts and results table.

## Web Dashboard API

The dashboard's frontend talks to a small JSON API, also usable directly:

| Method | Path                | Description                                              |
|--------|----------------------|------------------------------------------------------------|
| GET    | `/`                  | Serves the dashboard (`templates/index.html`)             |
| GET    | `/api/scans`         | Recent scan history (`?limit=N`, default 50)               |
| GET    | `/api/scans/<id>`    | Open ports, remediation, and matched CVEs for one scan     |
| GET    | `/api/stats`         | Aggregated stats: total scans, severity distribution, top open ports |
| POST   | `/api/scan`          | `{"target": "...", "ports": "top", "timeout": 1.0, "threads": 100, "banner": true}` — queues a scan on a background thread |
| GET    | `/api/scan/<queue_id>` | Poll status of a queued scan (`queued` / `running` / `done` / `error`) |

## Limitations & Roadmap

### Netpreter is actively developed. The current version has the following limitations, which are planned for future roadmap upgrades:

- **Exposure Detection Only (No Active Exploit Verification)**: Netpreter detects *exposure* (an open port and service presence), not confirmed *exploitability*. It does not actively launch payloads or confirm if a service is vulnerable to specific CVEs. Treat findings as a starting point for further authenticated review.
- **No Local Network Infrastructure or Wi-Fi Auditing**: The tool scans network layers via host sockets. It does not audit local infrastructure settings, physical router configurations, or wireless network security protocols (e.g., it cannot detect if a router is running outdated, vulnerable WPA/WPA2 wireless encryption instead of WPA3). Legacy infrastructure updates must be audited manually.
- **No Authentication or Password Security Auditing**: The tool does not test for weak/default credentials, execute brute-force password checks, or evaluate the strength of access control mechanics on exposed ports.
- **TCP-Connect Engine Only**: The architecture currently relies on standard TCP three-way handshakes. Deeper stealth scanning techniques (like SYN/FIN half-open scans) or UDP port auditing are not yet implemented.
- **No Active OS Detection**: Active operating system fingerprinting is outside the current scope. System intelligence is strictly limited to passive service banner grabbing.
- **IPv4-Centric Scanning**: While foundational address validation logic supports both IPv4 and IPv6 patterns, the core socket handling engine currently only operates end-to-end over IPv4 networks.
- **Per-Host Thread Distribution**: Multi-threading optimizations are designed to scale concurrently *across multiple target hosts* rather than utilizing aggressive multi-threading against a single individual host.
- **Missing Comprehensive Documentation Website**: A dedicated, end-to-end documentation platform explaining the inner architecture is currently planned, which will provide top-to-bottom insights.

---

## Legal Disclaimer & Ethical Use

This tool is developed strictly for **educational, academic, and authorized ethical testing purposes**. Scanning networks or hosts without explicit, prior written permission from the owner is illegal and constitutes a breach of computer crime laws. 

The developer assumes **absolute zero liability** and is not responsible for any misuse, damage, system disruption, or illegal activity caused by this software. By cloning, downloading, or executing Netpreter, you agree to utilize it solely within authorized scopes.


## License

This project is licensed under the GNU GPLv3 LICENSE - see the [LICENSE](LICENSE) file for details.
