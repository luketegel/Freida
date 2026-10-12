"""Orchestrator for headless Ghidra analysis.

Manages binary ingestion and environment detection, starts the analysis
backend (PyGhidra in-process by default, or a headless Ghidra MCP server),
drives decompilation across functions, detects system calls, and derives
the insights that feed the reports and model context.
"""

from __future__ import annotations

import hashlib
import logging
import os
import shlex
import shutil
import sys
import time
from pathlib import Path
from typing import Any

from freida.binary_insights import (
    callers_by_function,
    classify_origins,
    extract_indicators,
    hardening,
)
from freida.mcp_client import GhidraMCPClient
from freida.pyghidra_collector import PyGhidraCollector
from freida.syscall_detector import SyscallDetector, SyscallFinding

logger = logging.getLogger("freida.orchestrator")

TARGET_INFO_DEFAULT: dict[str, Any] = {
    "path": "",
    "name": "",
    "size_bytes": 0,
    "sha256": "",
    "md5": "",
    "file_type": "Unknown",
}

BACKENDS = ("pyghidra", "mcp")

UNSUPPORTED_SUFFIXES = {".class", ".jar", ".war"}

# Default headless Ghidra MCP server used for exploration and the `mcp` backend.
DEFAULT_MCP_PACKAGE = "ghidra-mcp[headless] @ git+https://github.com/LaurieWired/GhidraMCP"
DEFAULT_MCP_EXECUTABLE = "ghidra-mcp"


def compute_file_hashes(file_path: Path) -> tuple[str, str, int]:
    """Computes SHA256, MD5, and size for a target file."""
    sha256 = hashlib.sha256()
    md5 = hashlib.md5()
    size = 0

    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            sha256.update(chunk)
            md5.update(chunk)
            size += len(chunk)

    return sha256.hexdigest(), md5.hexdigest(), size


def detect_file_type(file_path: Path) -> str:
    """Detects the executable format from magic bytes."""
    suffix = file_path.suffix.lower()
    try:
        with open(file_path, "rb") as f:
            magic = f.read(16)
            if magic.startswith(b"\x7fELF"):
                bitness = "64-bit" if len(magic) > 4 and magic[4] == 2 else "32-bit"
                return f"Linux ELF ({bitness})"
            if magic.startswith(b"MZ"):
                return "Windows PE Executable"
            if magic.startswith(b"\xca\xfe\xba\xbe"):
                return "Mach-O Universal Binary"
            if magic.startswith((b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe")):
                return "macOS Mach-O Binary"
    except Exception as e:
        logger.debug("Error reading magic bytes: %s", e)

    return f"Unknown executable format ({suffix or 'raw'})"


class HeadlessOrchestrator:
    """Drives the headless Ghidra analysis workflow (PyGhidra or MCP backend)."""

    def __init__(
        self,
        target_path: str | Path,
        ghidra_install_dir: str | None = None,
        custom_mcp_cmd: str | None = None,
        server_url: str | None = None,
        project_dir: Path | None = None,
        extension_jar: Path | None = None,
        timeout: float = 120.0,
        backend: str | None = None,
        max_functions: int | None = None,
        decompile_timeout: int = 60,
    ) -> None:
        self.target_path = Path(target_path).resolve()
        if not self.target_path.exists():
            raise FileNotFoundError(f"Target binary not found: {self.target_path}")
        if self.target_path.suffix.lower() in UNSUPPORTED_SUFFIXES:
            raise ValueError(
                f"Unsupported target {self.target_path.name}: Java class/JAR files are not supported. "
                "Freida analyzes native executables (ELF, PE, Mach-O)."
            )

        self.ghidra_install_dir = (
            ghidra_install_dir
            or os.environ.get("GHIDRA_INSTALL_DIR")
            or ""
        )
        self.custom_mcp_cmd = custom_mcp_cmd
        self.server_url = server_url
        self.project_dir = project_dir
        self.extension_jar = extension_jar
        self.timeout = timeout
        self.max_functions = max_functions
        self.decompile_timeout = decompile_timeout

        if backend is None:
            backend = "mcp" if (server_url or custom_mcp_cmd) else "pyghidra"
        if backend not in BACKENDS:
            raise ValueError(f"Unknown backend '{backend}'. Expected one of: {', '.join(BACKENDS)}")
        self.backend = backend

        self.detector = SyscallDetector()
        self.metadata: dict[str, Any] = {}
        self.findings: list[SyscallFinding] = []
        self.decompiled_functions: dict[str, str] = {}
        self.facts: dict[str, Any] = {}
        self.exploration: dict[str, Any] = {}

    def collect_target_metadata(self) -> dict[str, Any]:
        """Gathers hash, size, and type information for the target."""
        sha256, md5, size = compute_file_hashes(self.target_path)
        file_type = detect_file_type(self.target_path)

        self.metadata = {
            "file_name": self.target_path.name,
            "absolute_path": str(self.target_path),
            "file_size_bytes": size,
            "file_size_formatted": f"{size / 1024:.2f} KB" if size < 1048576 else f"{size / (1024 * 1024):.2f} MB",
            "sha256": sha256,
            "md5": md5,
            "file_type": file_type,
            "analysis_time": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
            "backend": self.backend,
        }
        return self.metadata

    def build_mcp_command(self) -> list[str]:
        """Constructs the command to execute ghidra-mcp in headless mode."""
        if self.custom_mcp_cmd:
            # Split first so a target path containing spaces stays a single argument.
            return [
                part.replace("{binary}", str(self.target_path))
                for part in shlex.split(self.custom_mcp_cmd)
            ]

        # Check if ghidra-mcp CLI is available in PATH or python environment
        ghidra_mcp_bin = shutil.which(DEFAULT_MCP_EXECUTABLE)
        uvx_bin = shutil.which("uvx")
        uv_bin = shutil.which("uv")
        uv_runner = [uvx_bin] if uvx_bin else ([uv_bin, "tool", "run"] if uv_bin else None)

        if uv_runner:
            cmd = uv_runner + [
                "--python",
                "3.13",
                "--from",
                DEFAULT_MCP_PACKAGE,
                DEFAULT_MCP_EXECUTABLE,
                "--headless",
                "--binary",
                str(self.target_path),
            ]
        elif ghidra_mcp_bin:
            cmd = [ghidra_mcp_bin, "--headless", "--binary", str(self.target_path)]
        else:
            # Fallback to python3 / current interpreter
            python_bin = sys.executable or "python3"
            cmd = [
                python_bin,
                "-m",
                "ghidra_mcp.cli",
                "--headless",
                "--binary",
                str(self.target_path),
            ]

        if self.project_dir:
            cmd.extend(["--project", str(self.project_dir)])

        if self.extension_jar and Path(self.extension_jar).exists():
            cmd.extend(["--extension-jar", str(self.extension_jar)])

        return cmd

    def run_analysis(self) -> tuple[dict[str, Any], list[SyscallFinding]]:
        """Executes the complete headless Ghidra analysis workflow."""
        self.collect_target_metadata()
        logger.info("Beginning analysis on target: %s (%s)", self.target_path.name, self.metadata["file_type"])

        env = os.environ.copy()
        if self.ghidra_install_dir:
            env["GHIDRA_INSTALL_DIR"] = self.ghidra_install_dir

        # Setup backend
        client: GhidraMCPClient | PyGhidraCollector
        if self.backend == "pyghidra":
            client = PyGhidraCollector(
                target_path=self.target_path,
                ghidra_install_dir=self.ghidra_install_dir,
                project_dir=self.project_dir,
                max_functions=self.max_functions,
                decompile_timeout=self.decompile_timeout,
            )
        elif self.server_url:
            client = GhidraMCPClient(server_url=self.server_url, env=env, timeout=self.timeout)
        else:
            cmd = self.build_mcp_command()
            client = GhidraMCPClient(cmd=cmd, env=env, timeout=self.timeout)

        try:
            client.start()
            self._analyze_via_client(client)
        except Exception as e:
            logger.error("Error during %s analysis: %s", self.backend, e)
            raise
        finally:
            client.close()

        if isinstance(client, PyGhidraCollector):
            self.facts = client.facts
        self._add_insights()
        self.exploration = self._describe_exploration(client)

        logger.info("Analysis complete: detected %d system calls across target.", len(self.findings))
        return self.metadata, self.findings

    def _add_insights(self) -> None:
        """Derives callers, origins, indicators and hardening from the collected facts and the file header."""
        callers = callers_by_function(self.facts.get("functions", []))
        for fn in self.facts.get("functions", []):
            fn["callers"] = callers.get(fn.get("name"), [])
        classify_origins(self.facts)
        self.facts["indicators"] = extract_indicators(self.facts.get("strings", []))
        self.facts["hardening"] = hardening(self.target_path, self.facts)

    def _describe_exploration(self, client: GhidraMCPClient | PyGhidraCollector) -> dict[str, Any]:
        """Tells the model how to reach a Ghidra MCP server for deeper exploration."""
        info: dict[str, Any] = {"protocol": "mcp", "transport": "http" if self.server_url else "stdio"}
        if self.server_url:
            info["server_url"] = self.server_url
        else:
            info["launch_command"] = self.build_mcp_command()
        tools = getattr(client, "available_tools", None)
        info["tools"] = sorted(tools) if tools else []
        return info

    def _analyze_via_client(self, client: GhidraMCPClient | PyGhidraCollector) -> None:
        """Queries the Ghidra backend (PyGhidra or MCP) for program info, imports, and decompilation."""
        # 1. Retrieve Program Information
        prog_info = client.get_program_info()
        if prog_info:
            self.metadata["ghidra_program_name"] = prog_info.get("name", self.target_path.name)
            self.metadata["architecture"] = prog_info.get("language_id") or prog_info.get("architecture", "Unknown")
            self.metadata["compiler"] = prog_info.get("compiler_spec_id", "Unknown")
            self.metadata["image_base"] = prog_info.get("image_base", "Unknown")
            self.metadata["format"] = prog_info.get("format", self.metadata["file_type"])

        target_arch = self.metadata.get("architecture")

        # 2. Retrieve and Analyze Imported Symbols
        imports = client.list_imports()
        self.metadata["total_imports"] = len(imports)
        import_findings = self.detector.analyze_imports(imports, target_arch=target_arch) if imports else []
        logger.info("Detected %d syscalls from import table", len(import_findings))

        # 3. Retrieve Function List
        functions = client.list_functions(limit=100)
        self.metadata["total_functions"] = len(functions)
        logger.info("Decompiling %d functions in headless mode...", len(functions))

        # 4. Decompile Each Function and Scan for System Calls
        decompiled_count = 0
        for fn in functions:
            fn_name = fn.get("name") if isinstance(fn, dict) else str(fn)
            fn_addr = fn.get("address") if isinstance(fn, dict) else None
            callsites = fn.get("callsites") if isinstance(fn, dict) else None

            fn_findings: list[SyscallFinding] = []
            code = client.decompile_function(function_name=fn_name, address=fn_addr)
            if code:
                decompiled_count += 1
                self.decompiled_functions[fn_name] = code
                fn_findings = self.detector.analyze_decompiled_function(
                    function_name=fn_name,
                    code=code,
                    entry_address=fn_addr,
                    target_arch=target_arch,
                )
            if callsites:
                fn_findings = self.detector.analyze_callsites(
                    function_name=fn_name,
                    callsites=callsites,
                    decompiled_findings=fn_findings,
                    entry_address=fn_addr,
                    target_arch=target_arch,
                )
            self.findings.extend(fn_findings)

        # Report an import only when no call to it was found, so each API call is counted once.
        called = {f.name for f in self.findings}
        import_only = [f for f in import_findings if f.name not in called]
        self.findings = import_only + self.findings
        logger.info("%d imported syscall APIs have no call site found in decompiled functions", len(import_only))

        self.metadata["functions_decompiled"] = decompiled_count
        self.metadata["total_syscall_findings"] = len(self.findings)
        self.metadata["unique_syscalls"] = len(set(f.name for f in self.findings))

        # Facts for the model context bundle; the pyghidra backend replaces these with richer data.
        self.facts = {
            "program": prog_info or {},
            "imports": imports,
            "exports": [],
            "functions": [
                {
                    "name": fn.get("name") if isinstance(fn, dict) else str(fn),
                    "address": fn.get("address") if isinstance(fn, dict) else None,
                    "decompiled": self.decompiled_functions.get(fn.get("name") if isinstance(fn, dict) else str(fn)),
                }
                for fn in functions
            ],
            "strings": [],
        }
