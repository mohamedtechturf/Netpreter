#!/usr/bin/env python3
"""
Netpreter - Network Security & Configuration Audit Tool
Primary entry point, exposing all three execution modes:

  1. Quick Command CLI     python netpreter.py --target 192.168.1.1 --ports 1-1000
  2. Interactive Menu CLI  python netpreter.py
  3. Web Dashboard UI      python netpreter.py --web

See `netpreter/` for the implementation, or run:

    python netpreter.py --help
"""

import sys

from netpreter.cli import main

if __name__ == "__main__":
    sys.exit(main())
