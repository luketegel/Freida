"""Command-Line Interface for Ghidra Syscall Analyzer.

Enables automated, headless decompilation of native executables
via Ghidra MCP to extract system calls into Markdown reports.
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from pathlib import Path
from typing import Optional

from ghidra_syscall_analyzer.context_builder import build_context, build_facts, write_context, write_facts
from ghidra_syscall_analyzer.orchestrator import BACKENDS, HeadlessOrchestrator
from ghidra_syscall_analyzer.report_generator import MarkdownReportGenerator
from ghidra_syscall_analyzer.syscall_detector import SyscallDetector, SyscallFinding

logger = logging.getLogger("ghidra_syscall_analyzer")


def setup_logging(verbose: bool = False) -> None:
    """Configures logging format and verbosity."""
    level = logging.DEBUG if verbose else logging.INFO
    fmt = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    logging.basicConfig(level=level, format=fmt, datefmt="%H:%M:%S")


def run_mock_analysis(target_path: Path, output_file: Path) -> Path:
    """Runs a simulated analysis session with sample decompilations for testing/validation."""
    logger.info("Executing mock validation analysis on: %s", target_path.name)
    metadata = {
        "file_name": target_path.name,
        "absolute_path": str(target_path.resolve()),
        "file_size_bytes": 65536,
        "file_size_formatted": "64.00 KB",
        "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "md5": "d41d8cd98f00b204e9800998ecf8427e",
        "file_type": "ELF 64-bit / Linux Executable",
        "architecture": "x86:LE:64:default",
        "ghidra_program_name": target_path.name,
        "analysis_time": "2026-10-12 10:00:00 UTC",
        "backend": "mock",
        "functions_decompiled": 4,
    }

    detector = SyscallDetector()
    findings = []
    decompiled_samples = {
        "main": """int main(int argc, char **argv) {
    int fd = open("/etc/target_config", 0);
    if (fd < 0) {
        exit(1);
    }
    char buf[256];
    read(fd, buf, 256);
    close(fd);
    int sock = socket(2, 1, 0);
    connect(sock, (struct sockaddr *)&srv, sizeof(srv));
    sendto(sock, buf, 256, 0, (struct sockaddr *)&srv, sizeof(srv));
    return 0;
}""",
        "spawn_worker": """void spawn_worker(char *path) {
    pid_t pid = fork();
    if (pid == 0) {
        char *args[] = {"/bin/sh", "-c", path, NULL};
        execve("/bin/sh", args, NULL);
    } else {
        wait4(pid, NULL, 0, NULL);
    }
}""",
        "allocate_protected": """void *allocate_protected(size_t len) {
    void *ptr = mmap(NULL, len, 3, 0x22, -1, 0);
    mprotect(ptr, len, 7); // RWX permissions
    syscall(0x3c, 0); // direct exit syscall (0x3c = 60 = exit)
    return ptr;
}""",
        "raw_assembly_stub": """void raw_assembly_stub() {
    __asm__ volatile ("syscall");
}""",
    }

    for fn_name, code in decompiled_samples.items():
        found = detector.analyze_decompiled_function(fn_name, code, entry_address="0x401000")
        findings.extend(found)

    report_gen = MarkdownReportGenerator(
        metadata=metadata,
        findings=findings,
        decompiled_functions=decompiled_samples,
    )
    written_path = report_gen.write_to_file(output_file)
    logger.info("Mock analysis report successfully written to: %s", written_path)
    return written_path


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="ghidra-syscall-analyzer",
        description="Decompiles a native executable with headless Ghidra and reports all system calls in Markdown.",
    )
    parser.add_argument(
        "target",
        nargs="?",
        type=Path,
        help="Path to the executable to analyze (ELF, PE, Mach-O).",
    )
    parser.add_argument(
        "-b",
        "--binary",
        type=Path,
        dest="binary_opt",
        help="Alternative flag to specify the target executable path.",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        help="Path to output Markdown file (default: <target_name>_syscalls.md).",
    )
    parser.add_argument(
        "--context-out",
        type=Path,
        help="Path to output model context JSON (default: <target_name>_context.json).",
    )
    parser.add_argument(
        "--facts-out",
        type=Path,
        help="Path to output the full, uncapped facts JSON (default: <target_name>_facts.json).",
    )
    parser.add_argument(
        "--backend",
        choices=BACKENDS,
        help="Analysis backend: 'pyghidra' (in-process headless Ghidra, default) or 'mcp' "
        "(implied by --server-url / --mcp-cmd).",
    )
    parser.add_argument(
        "--mcp-cmd",
        type=str,
        help="Custom command to run ghidra-mcp headless (e.g., 'uvx --python 3.13 ...').",
    )
    parser.add_argument(
        "--server-url",
        type=str,
        help="Connect to an existing Ghidra MCP server URL (e.g. http://127.0.0.1:8081).",
    )
    parser.add_argument(
        "--ghidra-dir",
        type=str,
        help="Path to Ghidra installation directory (overrides GHIDRA_INSTALL_DIR).",
    )
    parser.add_argument(
        "--project-dir",
        type=Path,
        help="Optional directory to persist the Ghidra project across runs.",
    )
    parser.add_argument(
        "--extension-jar",
        type=Path,
        help="Path to GhidraMCP.jar extension if not pre-installed in Ghidra.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=120.0,
        help="Timeout in seconds for decompilation queries (default: 120.0s).",
    )
    parser.add_argument(
        "--max-functions",
        type=int,
        help="Maximum number of functions to collect with the pyghidra backend (default: all).",
    )
    parser.add_argument(
        "--decompile-timeout",
        type=int,
        default=60,
        help="Per-function decompilation timeout in seconds for the pyghidra backend (default: 60).",
    )
    parser.add_argument(
        "--mock-dry-run",
        action="store_true",
        help="Run simulated decompilation & report generation to test without Ghidra installed.",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable detailed debug logging.",
    )

    args = parser.parse_args(argv)
    setup_logging(args.verbose)

    target_file = args.binary_opt or args.target
    if not target_file:
        parser.error("A target executable path is required.")

    target_path = Path(target_file).resolve()
    if not target_path.exists():
        logger.error("Target file not found: %s", target_path)
        return 1

    # Default output paths
    output_path = args.output or Path(f"{target_path.stem}_syscalls.md")
    context_path = args.context_out or Path(f"{target_path.stem}_context.json")
    facts_path = args.facts_out or Path(f"{target_path.stem}_facts.json")

    if args.mock_dry_run:
        written_path = run_mock_analysis(target_path, output_path)
        print(f"\n[+] Analysis complete! Syscall report written to:\n    {written_path}\n")
        return 0

    try:
        orchestrator = HeadlessOrchestrator(
            target_path=target_path,
            ghidra_install_dir=args.ghidra_dir,
            custom_mcp_cmd=args.mcp_cmd,
            server_url=args.server_url,
            project_dir=args.project_dir,
            extension_jar=args.extension_jar,
            timeout=args.timeout,
            backend=args.backend,
            max_functions=args.max_functions,
            decompile_timeout=args.decompile_timeout,
        )

        metadata, findings = orchestrator.run_analysis()
        report_generator = MarkdownReportGenerator(
            metadata=metadata,
            findings=findings,
            decompiled_functions=orchestrator.decompiled_functions,
        )
        written_path = report_generator.write_to_file(output_path)
        facts_written = write_facts(
            build_facts(metadata, orchestrator.facts, findings, exploration=orchestrator.exploration),
            facts_path,
        )
        context = build_context(
            metadata=metadata,
            facts=orchestrator.facts,
            findings=findings,
            exploration=orchestrator.exploration,
            facts_file=facts_written.name,
        )
        context_written = write_context(context, context_path)
        print(f"\n[+] Success! Decompiled target with headless Ghidra ({orchestrator.backend}) and extracted {len(findings)} system call(s).")
        print(f"[+] Markdown report generated at:\n    {written_path}")
        print(f"[+] Model context bundle generated at:\n    {context_written}")
        print(f"[+] Full facts generated at:\n    {facts_written}\n")
        return 0

    except Exception as e:
        logger.error("Failed to analyze target: %s", e)
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 2


if __name__ == "__main__":
    sys.exit(main())
