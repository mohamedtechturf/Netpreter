"""
Netpreter - Network Security & Configuration Audit Tool
=========================================================

A lightweight, multi-threaded, dependency-free Python utility for auditing
the perimeter posture of hosts and small network ranges. Netpreter checks
for commonly-exposed, high-risk TCP services, correlates findings against a
curated risk database, grabs lightweight service banners where safe to do
so, and produces actionable, ranked remediation reports in text, JSON, or
CSV format.

This package is intended for authorized security assessments of systems you
own or are explicitly permitted to test.
"""

__version__ = "2.0.1"
__all__ = ["__version__"]
