# Netpreter

A lightweight, multi-threaded Python utility designed to scan, analyze, and interpret network configurations, active connections, and open ports[cite: 1]. Netpreter provides real-time security auditing and detailed diagnostics to help developers and system administrators assess network perimeter exposure[cite: 1].

## Features

- **Multi-Threaded Port & Service Scanning**: Fast, concurrent TCP connection checks across custom port ranges using Python's native threading capabilities[cite: 1].
- **Network Configuration Diagnostics**: Evaluates target host configurations, local interfaces, and routing visibility[cite: 1].
- **Security Assessment & Risk Mapping**: Checks detected open ports and services against built-in risk signatures to assign severity levels (`Critical`, `High`, `Medium`, `Low`, `Info`)[cite: 1].
- **Actionable Remediation Guidance**: Generates practical hardening advice and recommendations for closing or securing exposed services[cite: 1].
- **Automatic Audit Logging**: Automatically writes formatted audit reports and timestamps directly to the `logs/` directory[cite: 1].
- **Zero External Dependencies**: Developed entirely using the Python Standard Library for maximum portability and instant execution[cite: 1].

## Quick Start

### Prerequisites

- Python 3.6 or higher[cite: 1].

### Installation

Clone the repository to your local machine:

```bash
git clone [https://github.com/mohamedtechturf/Netpreter.git](https://github.com/mohamedtechturf/Netpreter.git)
cd Netpreter

```

### Usage

Run the script directly via Python:

```bash
python netpreter.py

```

Follow the interactive command-line prompts to specify target IP addresses, set custom port ranges, and start the network audit.

## Output & Logs

All audit sessions automatically output structured summary logs to the `logs/` directory:

```text
logs/
└── audit_2026-08-16_11-27-01.log

```

## License

This project is licensed under the MIT License - see the `LICENSE` file for details.

```

```
