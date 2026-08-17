
# Netpreter — Network Security & Configuration Audit Tool

[![MIT License](https://img.shields.io/badge/License-MIT-green.svg)](https://choosealicense.com/licenses/mit/)
![Linux](https://img.shields.io/badge/Supports-Linux-orange.svg)
![macOS](https://img.shields.io/badge/Supports-macOS-white.svg)
![windows](https://img.shields.io/badge/Supports-Windows-blue.svg)
[![github](https://img.shields.io/badge/github-repo-white?logo=github)](https://github.com/mohamedtechturf/Netpreter)
![Python](https://img.shields.io/badge/python-3.14.7-blue?logo=python)

A lightweight, multi-threaded Python utility for perimeter security audits
of hosts and small network ranges you own or are authorized to test. It
checks for commonly-exposed, high-risk TCP services, correlates results
against a curated risk database, optionally captures passive service
banners, and produces ranked, actionable remediation reports.


## Features

- **Multi-threaded TCP scanning** via `concurrent.futures`, with a
  per-host live progress bar.
- **Curated risk database** mapping 25+ common ports (SSH, RDP, SMB,
  Redis, MongoDB, Elasticsearch, etc.) to severity, plain-language
  impact, and specific remediation steps.
- **Multiple targets per run** — single host, comma-separated list, or a
  CIDR range (e.g. `10.0.0.0/28`), expanded and de-duplicated
  automatically, with a safety cap to prevent accidental huge scans.
- **Flexible port selection** — the curated `top` list, explicit
  comma-separated ports, numeric ranges (`1-1024`), or any mix of these.
- **Passive banner capture** — reads (never sends) the greeting a
  service offers on connect, for extra triage context.
- **Multi-format reporting** — human-readable text, structured JSON, or
  CSV, printed to the console and saved to a timestamped file.
- **Scriptable CLI or guided interactive menu** — pass flags for
  automation/CI, or run with no arguments for a prompt-driven flow.
- **Zero external dependencies** — Python standard library only.

## Prerequisites

- **Python:** Version 3.x or higher is required.
- **Terminal:** Access to a command-line interface (e.g., VS Code, terminal).

## Installation & Setup

1.  **Clone:** `git clone https://github.com/mohamedtechturf/Netpreter`
2.  **Navigate:** `cd Netpreter`
4.  **Execute:** Run `python main.py` and enter the target URL when prompted.

## Usage

**Interactive menu** (no arguments):

```bash
python main.py
```

**Scriptable CLI:**

```bash
# Audit a single host against the curated risk-port list
python main.py 192.168.1.10

# Audit multiple hosts and a small subnet, custom ports, JSON output
python main.py "10.0.0.5,10.0.0.6,10.0.0.0/29" -p 22,80,443,1-1024 -f json

# Faster/slower scanning
python main.py example.com -t 0.5 -T 200      # 0.5s timeout, 200 threads
python main.py example.com --no-banner        # skip banner capture
python main.py example.com --no-save          # print only, don't write a log
```

Run `python main.py --help` for the full flag reference.


## Project layout

```
Netpreter/
├── main.py                  # thin CLI entry point
├── netpreter/
│   ├── __init__.py          # package metadata/version
│   ├── database.py          # port -> risk/remediation reference data
│   ├── scanner.py           # target resolution + concurrent scan engine
│   ├── report.py            # text/JSON/CSV report rendering & export
│   └── cli.py                # argument parsing + interactive menu
├── tests/
│   └── test_netpreter.py    # unit + local-loopback integration tests
└── logs/                     # timestamped audit reports (created at runtime)
```

## How it works

1. **Resolve targets** — hostnames are DNS-resolved, IPs are validated,
   CIDR ranges are expanded to individual host addresses (capped at 1024
   hosts per run as a safety limit).
2. **Scan** — each requested port is probed with a standard TCP
   connect() handshake via a thread pool; a closed/filtered port is
   simply skipped.
3. **Classify** — every open port is looked up in the risk database and
   tagged `Critical` / `High` / `Medium` / `Low` / `Info`; ports outside
   the database still show up as unrecognized findings.
4. **Report** — findings are sorted by severity, summarized per host and
   overall, and rendered to text, JSON, or CSV.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
