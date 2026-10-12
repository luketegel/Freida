#!/usr/bin/env python3
"""Convenience launcher for the Freida CLI; works from a checkout without installing."""

import sys
from freida.cli import main

if __name__ == "__main__":
    sys.exit(main())
