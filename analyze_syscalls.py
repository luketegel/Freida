#!/usr/bin/env python3
"""Convenience launcher script for Ghidra Syscall Analyzer."""

import sys
from ghidra_syscall_analyzer.cli import main

if __name__ == "__main__":
    sys.exit(main())
