
# Netpreter 🌐

[![MIT License](https://img.shields.io/badge/License-MIT-green.svg)](https://choosealicense.com/licenses/mit/)
![Linux](https://img.shields.io/badge/Supports-Linux-orange.svg)
![macOS](https://img.shields.io/badge/Supports-macOS-white.svg)
![windows](https://img.shields.io/badge/Supports-Windows-blue.svg)
[![github](https://img.shields.io/badge/github-repo-white?logo=github)](https://github.com/mohamedtechturf/Netpreter)
![Python](https://img.shields.io/badge/python-3.14.7-blue?logo=python)

A lightweight, multi-threaded Python utility designed to scan, analyze, and interpret network configurations, active connections, and open ports. Netpreter provides real-time security auditing and detailed diagnostics to help developers and system administrators assess network perimeter exposure


## Features

- 🔍 Multi-Threaded Port & Service Scanning: Fast, concurrent TCP connection checks across custom port ranges using Python's native threading capabilities.
- 📡 Network Configuration Diagnostics: Evaluates target host configurations, local interfaces, and routing visibility.
- 🔰 Security Assessment & Risk Mapping: Checks detected open ports and services against built-in risk signatures to assign severity levels (Critical, High, Medium, Low, Info).
- ⚡ Actionable Remediation Guidance: Generates practical hardening advice and recommendations for closing or securing exposed services.
- ⚙️ Automatic Audit Logging: Automatically writes formatted audit reports and timestamps directly to the logs/ directory.
- 📜 Zero External Dependencies: Developed entirely using the Python Standard Library for maximum portability and instant execution.

## Prerequisites

- **Python:** Version 3.x or higher is required.
- **Terminal:** Access to a command-line interface (e.g., VS Code, terminal).

## Installation & Setup

1.  **Clone:** `git clone https://github.com/mohamedtechturf/Netpreter`
2.  **Navigate:** `cd Netpreter`
4.  **Execute:** Run `python main.py` and enter the target URL when prompted.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
