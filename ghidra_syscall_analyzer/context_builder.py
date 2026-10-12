"""Model Context and Facts Builders.

Two JSON outputs describe an analyzed binary for an AI model:

- **Facts** (`<target>_facts.json`): everything collected, uncapped: program
  metadata, hardening, memory map, imports/exports, every function with its
  signature, callers, callsites and decompiled code, syscall findings, all
  strings and global data with cross-references, used data types, and
  indicators.
- **Context** (`<target>_context.json`): the same sections, relevance-ranked
  and capped so it fits a model's context window. A `truncated` section lists
  what was cut and names the facts file holding the rest.

Everything carries an address so the model can request more detail from a
Ghidra MCP server during later exploration.
"""

from __future__ import annotations

import collections
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from ghidra_syscall_analyzer.syscall_detector import SyscallFinding

SCHEMA_VERSION = 2
FACTS_SCHEMA_VERSION = 1

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
    """Caps that keep the context bundle small enough for a model context window."""
    max_decompiled_functions: int = 40
    max_decompiled_lines: int = 200
    max_strings: int = 500
    max_string_length: int = 200
    max_globals: int = 300
    max_data_types: int = 100
    max_fields_per_type: int = 32
    max_indicators: int = 200
    max_refs_per_item: int = 10


def _short_name(qualified: str) -> str:
    # Mach-O symbols carry a leading underscore (`_main`).
    return qualified.replace("::", ".").split(".")[-1].lstrip("_")


def _ref_names(referenced_by: List[Any]) -> List[str]:
    """Unique referencing function names, in first-seen order."""
    names: List[str] = []
    for ref in referenced_by or []:
        name = ref.get("function") if isinstance(ref, dict) else str(ref)
        if name and name not in names:
            names.append(name)
    return names


def _syscall_summary(findings: List[SyscallFinding]) -> Dict[str, Any]:
    return {
        "total": len(findings),
        "unique": sorted({f.name for f in findings}),
        "by_severity": dict(collections.Counter(f.severity for f in findings)),
        "by_category": dict(collections.Counter(f.category for f in findings)),
    }


def _finding_dict(f: SyscallFinding) -> Dict[str, Any]:
    return {
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


def _function_entry(fn: Dict[str, Any], findings_by_function: Dict[str, List[SyscallFinding]]) -> Dict[str, Any]:
    return {
        "name": fn.get("name"),
        "address": fn.get("address"),
        "size": fn.get("size"),
        "is_thunk": fn.get("is_thunk", False),
        "signature": fn.get("signature"),
        "calling_convention": fn.get("calling_convention"),
        "callers": fn.get("callers", []),
        "callees": fn.get("callees", []),
        "callsites": fn.get("callsites", []),
        "syscalls": sorted({f.name for f in findings_by_function.get(fn.get("name"), [])}),
    }


def _group_findings(findings: List[SyscallFinding]) -> Dict[str, List[SyscallFinding]]:
    grouped: Dict[str, List[SyscallFinding]] = collections.defaultdict(list)
    for f in findings:
        grouped[f.function_name].append(f)
    return grouped


def _common_sections(metadata: Dict[str, Any], facts: Dict[str, Any], findings: List[SyscallFinding]) -> Dict[str, Any]:
    return {
        "target": {key: metadata[key] for key in TARGET_KEYS if key in metadata},
        "program": facts.get("program", {}),
        "program_metadata": facts.get("program_metadata", {}),
        "hardening": facts.get("hardening", {}),
        "memory_map": facts.get("memory_map", []),
        "imports": facts.get("imports", []),
        "exports": facts.get("exports", []),
        "syscall_summary": _syscall_summary(findings),
        "syscall_findings": [_finding_dict(f) for f in findings],
    }


def build_facts(
    metadata: Dict[str, Any],
    facts: Dict[str, Any],
    findings: List[SyscallFinding],
    exploration: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Builds the uncapped facts document: every collected item, with full decompiled code."""
    findings_by_function = _group_findings(findings)
    functions = []
    for fn in facts.get("functions", []):
        entry = _function_entry(fn, findings_by_function)
        if fn.get("decompiled"):
            entry["decompiled"] = fn["decompiled"]
        functions.append(entry)

    collection_limits = facts.get("limits", {})
    output = {"schema_version": FACTS_SCHEMA_VERSION}
    output.update(_common_sections(metadata, facts, findings))
    output.update({
        "functions": functions,
        "strings": facts.get("strings", []),
        "globals": facts.get("globals", []),
        "data_types": facts.get("data_types", []),
        "indicators": facts.get("indicators", []),
        "collection_limits": collection_limits,
        "exploration": exploration or {},
    })
    return output


def _rank_by_references(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Most-referenced first; unreferenced items keep their address order at the end."""
    indexed = list(enumerate(items))
    indexed.sort(key=lambda pair: (-len(_ref_names(pair[1].get("referenced_by", []))), pair[0]))
    return [item for _, item in indexed]


def _compact_string(s: Dict[str, Any], limits: ContextLimits) -> Dict[str, Any]:
    value = str(s.get("value", ""))
    item: Dict[str, Any] = {"address": s.get("address"), "value": value[: limits.max_string_length]}
    if len(value) > limits.max_string_length:
        item["truncated"] = True
    for key in ("section", "encoding"):
        if s.get(key) is not None:
            item[key] = s[key]
    item["referenced_by"] = _ref_names(s.get("referenced_by", []))[: limits.max_refs_per_item]
    return item


def _compact_global(g: Dict[str, Any], limits: ContextLimits) -> Dict[str, Any]:
    item = {key: g.get(key) for key in ("address", "label", "type", "size", "section", "value_preview")}
    if g.get("points_to"):
        item["points_to"] = g["points_to"]
    item["referenced_by"] = _ref_names(g.get("referenced_by", []))[: limits.max_refs_per_item]
    return item


def _compact_type(t: Dict[str, Any], limits: ContextLimits) -> Dict[str, Any]:
    item = {key: t.get(key) for key in ("name", "kind", "size", "source_archive")}
    fields = t.get("fields")
    if fields is not None:
        item["fields"] = fields[: limits.max_fields_per_type]
        if len(fields) > limits.max_fields_per_type:
            item["fields_omitted"] = len(fields) - limits.max_fields_per_type
    values = t.get("values")
    if values is not None:
        kept = list(values.items())[: limits.max_fields_per_type]
        item["values"] = dict(kept)
        if len(values) > len(kept):
            item["values_omitted"] = len(values) - len(kept)
    if t.get("base_type") is not None:
        item["base_type"] = t["base_type"]
    item["used_by"] = list(t.get("used_by", []))[: limits.max_refs_per_item]
    return item


def build_context(
    metadata: Dict[str, Any],
    facts: Dict[str, Any],
    findings: List[SyscallFinding],
    limits: Optional[ContextLimits] = None,
    exploration: Optional[Dict[str, Any]] = None,
    facts_file: Optional[str] = None,
) -> Dict[str, Any]:
    """Builds the model-sized context bundle from analysis metadata, facts, and findings."""
    limits = limits or ContextLimits()
    program = facts.get("program", {})
    entry_points = set(program.get("entry_points", []))
    findings_by_function = _group_findings(findings)

    functions_out: List[Dict[str, Any]] = []
    decompile_candidates: List[Dict[str, Any]] = []
    for fn in facts.get("functions", []):
        entry = _function_entry(fn, findings_by_function)
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
    strings_out = [_compact_string(s, limits) for s in _rank_by_references(all_strings)[: limits.max_strings]]

    all_globals = facts.get("globals", [])
    globals_out = [_compact_global(g, limits) for g in _rank_by_references(all_globals)[: limits.max_globals]]

    # Types used by functions with syscall findings first, then by how widely they are used.
    flagged_functions = set(findings_by_function)
    all_types = facts.get("data_types", [])
    ranked_types = sorted(
        enumerate(all_types),
        key=lambda pair: (
            not (set(pair[1].get("used_by", [])) & flagged_functions),
            -len(pair[1].get("used_by", [])),
            pair[0],
        ),
    )
    types_out = [_compact_type(t, limits) for _, t in ranked_types[: limits.max_data_types]]

    all_indicators = facts.get("indicators", [])
    indicators_out = all_indicators[: limits.max_indicators]

    collection_limits = facts.get("limits", {})
    functions_total = collection_limits.get("functions_total", len(functions_out))

    output = {"schema_version": SCHEMA_VERSION}
    output.update(_common_sections(metadata, facts, findings))
    output.update({
        "functions": functions_out,
        "strings": strings_out,
        "globals": globals_out,
        "data_types": types_out,
        "indicators": indicators_out,
        "truncated": {
            "functions_not_collected": max(functions_total - len(functions_out), 0),
            "decompiled_omitted": decompiled_omitted,
            "decompiled_line_capped": line_capped,
            "strings_omitted": max(len(all_strings) - len(strings_out), 0),
            "globals_omitted": max(len(all_globals) - len(globals_out), 0),
            "data_types_omitted": max(len(all_types) - len(types_out), 0),
            "data_types_collection_capped": bool(collection_limits.get("data_types_truncated", False)),
            "indicators_omitted": max(len(all_indicators) - len(indicators_out), 0),
            "full_facts_file": facts_file,
            "note": "Everything cut here is in full_facts_file; use the exploration server for anything beyond it.",
        },
        "exploration": exploration or {},
    })
    return output


def _write_json(document: Dict[str, Any], output_path: Union[str, Path]) -> Path:
    out_file = Path(output_path).resolve()
    out_file.parent.mkdir(parents=True, exist_ok=True)
    out_file.write_text(json.dumps(document, indent=2, default=str), encoding="utf-8")
    return out_file


def write_context(context: Dict[str, Any], output_path: Union[str, Path]) -> Path:
    """Writes the context bundle as pretty-printed JSON."""
    return _write_json(context, output_path)


def write_facts(facts: Dict[str, Any], output_path: Union[str, Path]) -> Path:
    """Writes the uncapped facts document as pretty-printed JSON."""
    return _write_json(facts, output_path)
