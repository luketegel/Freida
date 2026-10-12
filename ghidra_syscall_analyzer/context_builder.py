"""Model Context Bundle Builder.

Assembles a compact, JSON-serializable summary of an analyzed binary for an
AI model: verified target metadata, program layout, imports/exports, every
function with its callsites, detected system calls, selected decompiled code,
and strings. Everything carries an address so the model can request more
detail from a Ghidra MCP server during later exploration.
"""

from __future__ import annotations

import collections
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from ghidra_syscall_analyzer.syscall_detector import SyscallFinding

SCHEMA_VERSION = 1

ENTRY_FUNCTION_NAMES = {"main", "entry", "_start", "WinMain", "wWinMain", "DllMain", "init", "start"}

TARGET_KEYS = (
    "file_name",
    "file_size_bytes",
    "sha256",
    "md5",
    "file_type",
    "architecture",
    "compiler",
    "image_base",
    "analysis_time",
    "backend",
)


@dataclass
class ContextLimits:
    """Caps that keep the bundle small enough for a model context window."""
    max_decompiled_functions: int = 40
    max_decompiled_lines: int = 200
    max_strings: int = 500
    max_string_length: int = 200


def _short_name(qualified: str) -> str:
    # Mach-O symbols carry a leading underscore (`_main`).
    return qualified.replace("::", ".").split(".")[-1].lstrip("_")


def build_context(
    metadata: Dict[str, Any],
    facts: Dict[str, Any],
    findings: List[SyscallFinding],
    limits: Optional[ContextLimits] = None,
    exploration: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Builds the model context bundle from analysis metadata, facts, and findings."""
    limits = limits or ContextLimits()
    program = facts.get("program", {})
    entry_points = set(program.get("entry_points", []))

    findings_by_function: Dict[str, List[SyscallFinding]] = collections.defaultdict(list)
    for f in findings:
        findings_by_function[f.function_name].append(f)

    functions_out: List[Dict[str, Any]] = []
    decompile_candidates: List[Dict[str, Any]] = []
    for fn in facts.get("functions", []):
        entry = {
            "name": fn.get("name"),
            "address": fn.get("address"),
            "size": fn.get("size"),
            "is_thunk": fn.get("is_thunk", False),
            "callees": fn.get("callees", []),
            "callsites": fn.get("callsites", []),
            "syscalls": sorted({f.name for f in findings_by_function.get(fn.get("name"), [])}),
        }
        if fn.get("program"):
            entry["program"] = fn["program"]
        functions_out.append(entry)

        is_entry = fn.get("address") in entry_points or _short_name(fn.get("name") or "") in ENTRY_FUNCTION_NAMES
        if fn.get("decompiled") and (entry["syscalls"] or is_entry):
            decompile_candidates.append({"entry": entry, "code": fn["decompiled"], "is_entry": is_entry})

    # Entry points first, then the functions with the most syscall findings.
    decompile_candidates.sort(key=lambda c: (not c["is_entry"], -len(c["entry"]["syscalls"])))
    line_capped: List[str] = []
    for candidate in decompile_candidates[: limits.max_decompiled_functions]:
        lines = candidate["code"].splitlines()
        if len(lines) > limits.max_decompiled_lines:
            lines = lines[: limits.max_decompiled_lines]
            line_capped.append(candidate["entry"]["name"])
        candidate["entry"]["decompiled"] = "\n".join(lines)
    decompiled_omitted = [c["entry"]["name"] for c in decompile_candidates[limits.max_decompiled_functions:]]

    all_strings = facts.get("strings", [])
    strings_out = []
    for s in all_strings[: limits.max_strings]:
        value = s.get("value", "")
        item = dict(s)
        if len(value) > limits.max_string_length:
            item["value"] = value[: limits.max_string_length]
            item["truncated"] = True
        strings_out.append(item)

    collection_limits = facts.get("limits", {})
    functions_total = collection_limits.get("functions_total", len(functions_out))

    severities = collections.Counter(f.severity for f in findings)
    categories = collections.Counter(f.category for f in findings)

    return {
        "schema_version": SCHEMA_VERSION,
        "target": {key: metadata[key] for key in TARGET_KEYS if key in metadata},
        "program": program,
        "imports": facts.get("imports", []),
        "exports": facts.get("exports", []),
        "syscall_summary": {
            "total": len(findings),
            "unique": sorted({f.name for f in findings}),
            "by_severity": dict(severities),
            "by_category": dict(categories),
        },
        "syscall_findings": [
            {
                "name": f.name,
                "category": f.category,
                "severity": f.severity,
                "detection_type": f.detection_type,
                "function": f.function_name,
                "function_address": f.address,
                "callsite_address": f.callsite_address,
                "line": f.line_number,
                "arguments": f.arguments,
                "syscall_number": f.syscall_number,
                "code": f.code_snippet,
            }
            for f in findings
        ],
        "functions": functions_out,
        "strings": strings_out,
        "truncated": {
            "functions_not_collected": max(functions_total - len(functions_out), 0),
            "decompiled_omitted": decompiled_omitted,
            "decompiled_line_capped": line_capped,
            "strings_omitted": max(len(all_strings) - len(strings_out), 0),
            "note": "Use the exploration server with the listed addresses to retrieve anything omitted here.",
        },
        "exploration": exploration or {},
    }


def write_context(context: Dict[str, Any], output_path: Union[str, Path]) -> Path:
    """Writes the context bundle as pretty-printed JSON."""
    out_file = Path(output_path).resolve()
    out_file.parent.mkdir(parents=True, exist_ok=True)
    out_file.write_text(json.dumps(context, indent=2, default=str), encoding="utf-8")
    return out_file
