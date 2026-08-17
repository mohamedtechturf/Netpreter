#!/usr/bin/env python3
"""
Netpreter - Network Security & Configuration Audit Tool
Entry point. See `netpreter/` for the implementation, or run:

    python main.py --help
"""

import sys

from netpreter.cli import main

if __name__ == "__main__":
    sys.exit(main())
