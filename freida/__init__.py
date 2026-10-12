"""Freida: static malware triage for native executables.

Decompiles ELF, PE and Mach-O binaries with headless Ghidra, detects every
system call, and writes Markdown and PDF reports, a model context bundle,
and an optional AI Behavioral Overview. A local web UI wraps the whole flow.
"""

__version__ = "1.0.0"
__author__ = "The Freida Team"
