"""Markdown Report Generator for Freida.

Produces comprehensive, GitHub-flavored Markdown reports detailing
detected system calls, category distributions, severity evaluations,
and decompiled evidence snippets.
"""

from __future__ import annotations

import collections
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from freida.syscall_detector import SyscallFinding

BACKEND_LABELS = {
    "pyghidra": "Ghidra Headless (No GUI) | PyGhidra in-process",
    "mcp": "Ghidra Headless (No GUI) | Model Context Protocol",
    "mock": "Mock dry run (simulated data, target not decompiled)",
}


def code_cell(value: Any) -> str:
    """Renders a value as inline code that is safe inside a Markdown table cell."""
    text = str(value).replace("\n", " ").replace("|", "\\|")
    if "`" in text:
        return f"`` {text} ``"
    return f"`{text}`"


class MarkdownReportGenerator:
    """Generates rich Markdown documentation from analysis results."""

    def __init__(
        self,
        metadata: Dict[str, Any],
        findings: List[SyscallFinding],
        decompiled_functions: Optional[Dict[str, str]] = None,
    ) -> None:
        self.metadata = metadata
        self.findings = findings
        self.decompiled_functions = decompiled_functions or {}

    def generate(self) -> str:
        """Constructs the full Markdown document content."""
        sections = [
            self._render_header(),
            self._render_target_overview(),
            self._render_dashboard_metrics(),
            self._render_category_summary(),
            self._render_security_impact(),
            self._render_detailed_syscall_table(),
            self._render_decompiled_evidence(),
            self._render_methodology(),
        ]
        return "\n\n".join(sections)

    def write_to_file(self, output_path: Union[str, Path]) -> Path:
        """Writes the generated report to the designated output file."""
        out_file = Path(output_path).resolve()
        out_file.parent.mkdir(parents=True, exist_ok=True)
        content = self.generate()
        out_file.write_text(content, encoding="utf-8")
        return out_file

    def _render_header(self) -> str:
        name = self.metadata.get("file_name", "Target Binary")
        backend = self.metadata.get("backend", "mcp")
        mode = BACKEND_LABELS.get(backend, backend)
        return f"""# 🛡️ System Call Analysis Report: `{name}`

> **Automated Headless Binary Decompilation via Ghidra**  
> **Analysis Date:** {self.metadata.get('analysis_time', 'N/A')}  
> **Analysis Mode:** {mode}"""

    def _render_target_overview(self) -> str:
        return f"""## 📦 Target Binary Information

| Attribute | Value |
| :--- | :--- |
| **File Name** | {code_cell(self.metadata.get('file_name', 'Unknown'))} |
| **Absolute Path** | {code_cell(self.metadata.get('absolute_path', 'Unknown'))} |
| **File Format** | {code_cell(self.metadata.get('file_type', 'Unknown'))} |
| **Architecture** | {code_cell(self.metadata.get('architecture', self.metadata.get('format', 'Auto-detected')))} |
| **File Size** | {self.metadata.get('file_size_formatted', 'Unknown')} ({self.metadata.get('file_size_bytes', 0):,} bytes) |
| **SHA-256** | `{self.metadata.get('sha256', 'N/A')}` |
| **MD-5** | `{self.metadata.get('md5', 'N/A')}` |
| **Ghidra Program Name** | {code_cell(self.metadata.get('ghidra_program_name', self.metadata.get('file_name')))} |"""

    def _render_dashboard_metrics(self) -> str:
        total_findings = len(self.findings)
        unique_syscalls = len(set(f.name for f in self.findings))
        funcs_decompiled = self.metadata.get("functions_decompiled", len(self.decompiled_functions))

        severities = collections.Counter(f.severity for f in self.findings)
        crit = severities.get("CRITICAL", 0)
        high = severities.get("HIGH", 0)
        med = severities.get("MEDIUM", 0)
        low = severities.get("LOW", 0)
        info = severities.get("INFO", 0)

        return f"""## 📊 Analysis Dashboard

| Metric | Count | Details |
| :--- | :---: | :--- |
| **Total Functions Decompiled** | **{funcs_decompiled}** | Analyzed via Ghidra Decompiler |
| **Total Syscall Invocations** | **{total_findings}** | Detected across all functions & imports |
| **Unique System Calls** | **{unique_syscalls}** | Distinct system call primitives |
| **Critical Severity Calls** | **{crit}** | High-impact actions (Injection, Exec, Arbitrary Memory) |
| **High Severity Calls** | **{high}** | Process spawns, Memory protection changes, Elevated privileges |
| **Medium Severity Calls** | **{med}** | Network sockets, File creation/deletion, IPC |
| **Low / Info Severity Calls** | **{low + info}** | File reads, Clocks, System telemetry |"""

    def _render_category_summary(self) -> str:
        categories = collections.Counter(f.category for f in self.findings)
        if not categories:
            return "## 📂 System Call Categories\n\n*No system calls detected.*"

        rows = []
        max_count = max(categories.values()) if categories else 1
        for cat, count in categories.most_common():
            bar_len = int((count / max_count) * 20)
            bar = "█" * bar_len + "░" * (20 - bar_len)
            rows.append(f"| **{cat}** | `{count}` | `{bar}` {count} call(s) |")

        table = "\n".join(rows)
        return f"""## 📂 System Call Categories

| Category | Count | Distribution |
| :--- | :---: | :--- |
{table}"""

    def _render_security_impact(self) -> str:
        categories = set(f.category for f in self.findings)
        observations = []

        if "Direct Syscall" in categories:
            direct_funcs = [f.function_name for f in self.findings if f.category == "Direct Syscall"]
            observations.append(
                f"- ⚠️ **Direct Kernel Entry:** Raw syscall instructions that bypass libc wrappers in: `{', '.join(sorted(set(direct_funcs)))}`."
            )
        if "Process & Execution" in categories:
            exec_calls = [f.name for f in self.findings if f.category == "Process & Execution"]
            observations.append(
                f"- ⚠️ **Process Execution Capabilities:** Detected routines capable of spawning or altering processes: `{', '.join(sorted(set(exec_calls)))}`."
            )
        if "Memory Management" in categories:
            mem_calls = [f.name for f in self.findings if f.category == "Memory Management"]
            observations.append(
                f"- ⚠️ **Dynamic Memory & Page Protection:** Target manages memory allocations and page permissions: `{', '.join(sorted(set(mem_calls)))}`."
            )
        if "Networking & Sockets" in categories:
            net_calls = [f.name for f in self.findings if f.category == "Networking & Sockets"]
            observations.append(
                f"- 🌐 **Network Communication:** Target initializes network sockets or connections: `{', '.join(sorted(set(net_calls)))}`."
            )
        if "File I/O" in categories:
            io_calls = [f.name for f in self.findings if f.category == "File I/O"]
            observations.append(
                f"- 📁 **Filesystem Operations:** Target accesses, modifies, or inspects files: `{', '.join(sorted(set(io_calls)))}`."
            )
        if "Security & Privileges" in categories:
            sec_calls = [f.name for f in self.findings if f.category == "Security & Privileges"]
            observations.append(
                f"- 🔒 **Privilege / Capability Management:** Target interacts with system credentials or isolation controls: `{', '.join(sorted(set(sec_calls)))}`."
            )

        if not observations:
            observations.append("- ✅ **Low Risk:** No high-risk privileged system calls detected.")

        obs_text = "\n".join(observations)
        return f"""## 🔍 Security & Behavioral Observations

{obs_text}"""

    def _render_detailed_syscall_table(self) -> str:
        if not self.findings:
            return "## 📋 System Calls Inventory\n\n*No system calls detected.*"

        rows = []
        for f in self.findings:
            sev_badge = {
                "CRITICAL": "🔴 CRITICAL",
                "HIGH": "🟠 HIGH",
                "MEDIUM": "🟡 MEDIUM",
                "LOW": "🟢 LOW",
                "INFO": "⚪ INFO",
            }.get(f.severity, f.severity)

            loc = code_cell(f.function_name)
            if f.callsite_address:
                loc += f"<br>call @ {code_cell(f.callsite_address)}"
            elif f.address:
                loc += f"<br>{code_cell(f.address)}"

            det_type = f.detection_type.replace("_", " ").title()
            args_snippet = code_cell(f"{f.arguments[:40]}...") if len(f.arguments) > 40 else (code_cell(f.arguments) if f.arguments else "—")

            rows.append(
                f"| **{code_cell(f.name)}** | {f.category} | {sev_badge} | {loc} | {f.line_number or '—'} | {det_type} | {args_snippet} |"
            )

        table = "\n".join(rows)
        return f"""## 📋 System Calls Inventory

| Syscall / API | Category | Severity | Function / Address | Line | Type | Arguments / Context |
| :--- | :--- | :---: | :--- | :---: | :--- | :--- |
{table}"""

    def _render_decompiled_evidence(self) -> str:
        if not self.findings:
            return ""

        # Group findings by function
        by_func: Dict[str, List[SyscallFinding]] = collections.defaultdict(list)
        for f in self.findings:
            by_func[f.function_name].append(f)

        sections = ["## 🔬 Decompiled Evidence & Callsite Context"]

        for func_name, func_findings in by_func.items():
            if func_name == "[IMPORT_TABLE]":
                continue

            findings_list = ", ".join(f"`{f.name}`" for f in func_findings)
            sections.append(f"### Function: `{func_name}`")
            sections.append(f"**Detected System Calls:** {findings_list}\n")

            # Show code snippets for each finding in this function
            snippets = []
            for f in func_findings:
                snippets.append(
                    f"- **Line {f.line_number}** (`{f.name}` - {f.category}):\n"
                    f"  ```c\n"
                    f"  {f.code_snippet}\n"
                    f"  ```"
                )
            sections.append("\n".join(snippets))

            # Include broader decompiled function excerpt if available
            decompiled_body = self.decompiled_functions.get(func_name)
            if decompiled_body:
                # Truncate if exceptionally long
                lines = decompiled_body.splitlines()
                preview = "\n".join(lines[:40])
                if len(lines) > 40:
                    preview += f"\n  // ... [{len(lines) - 40} lines truncated] ..."
                sections.append(
                    f"<details>\n<summary><b>View Full Decompiled Function:</b> <code>{func_name}</code></summary>\n\n"
                    f"```c\n{preview}\n```\n</details>\n"
                )

        return "\n\n".join(sections)

    def _render_methodology(self) -> str:
        backend = self.metadata.get("backend", "mcp")
        if backend == "pyghidra":
            engine = "- **Decompilation Engine:** Ghidra Decompiler (`DecompInterface`) driven in-process via PyGhidra."
        elif backend == "mock":
            engine = "- **Decompilation Engine:** None. Mock dry run with built-in sample code; the target was not decompiled."
        else:
            engine = (
                "- **Decompilation Engine:** Ghidra Decompiler via a Ghidra MCP server.\n"
                "- **Protocol:** Model Context Protocol (MCP) JSON-RPC 2.0 stdio / HTTP bridge."
            )
        return f"""## ⚙️ Methodology & Tooling

This report was generated using **Freida** operating in full **Headless Mode**:
{engine}
- **Headless Execution:** Fully automated headless analysis without requiring the Ghidra graphical user interface (GUI).
- **Detection Scope:** Covers direct assembly syscall instructions (`syscall`, `sysenter`, `int 0x80`, `svc #0`), POSIX / libc system call wrappers, Windows Native NT and Win32 system APIs, and macOS Mach traps in native executables (ELF, PE, Mach-O)."""
