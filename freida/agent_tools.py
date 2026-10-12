"""Agent Lookup Tools.

Read-only lookups over the uncapped facts file that the report agent can
call (Gemini function calling) to fetch detail the context left out: full
decompiled functions, cross-references, string searches, and data types.
"""

from __future__ import annotations

import difflib
import json
from collections.abc import Callable
from typing import Any

MAX_RESULT_BYTES = 16 * 1024
MAX_STRING_HITS = 30
MAX_STRING_VALUE = 200

FUNCTION_DECLARATIONS: list[dict[str, Any]] = [
    {
        "name": "get_function",
        "description": (
            "Full details of one function: signature, complete decompiled C, callers, callees, "
            "call sites and syscall findings. Use for functions whose code is not in the context."
        ),
        "parametersJsonSchema": {
            "type": "object",
            "properties": {
                "name_or_address": {
                    "type": "string",
                    "description": "Function name (e.g. _process_execution) or entry address (e.g. 100000608).",
                },
            },
            "required": ["name_or_address"],
        },
    },
    {
        "name": "get_references",
        "description": "Which functions reference a string, global variable or function at an address, and from where.",
        "parametersJsonSchema": {
            "type": "object",
            "properties": {
                "address": {"type": "string", "description": "Address of a string, global or function."},
            },
            "required": ["address"],
        },
    },
    {
        "name": "search_strings",
        "description": "Case-insensitive substring search over every string in the binary, with referencing functions.",
        "parametersJsonSchema": {
            "type": "object",
            "properties": {"query": {"type": "string", "description": "Text to search for."}},
            "required": ["query"],
        },
    },
    {
        "name": "get_data_type",
        "description": "All fields (offset, name, type, size) of a struct/union, values of an enum, or a typedef's base.",
        "parametersJsonSchema": {
            "type": "object",
            "properties": {"name": {"type": "string", "description": "Data type name, e.g. sockaddr."}},
            "required": ["name"],
        },
    },
]


def normalize_address(address: Any) -> str:
    """Canonical form for address comparison: no 0x prefix, lowercase, no leading zeros."""
    text = str(address or "").strip().lower()
    if ":" in text:
        space, _, offset = text.rpartition(":")
        return f"{space}:{offset.lstrip('0') or '0'}"
    if text.startswith("0x"):
        text = text[2:]
    return text.lstrip("0") or "0"


def _bare(name: str) -> str:
    return name.split("::")[-1].lstrip("_")


def _ref_names(referenced_by: list[Any]) -> list[str]:
    names: list[str] = []
    for ref in referenced_by or []:
        name = ref.get("function") if isinstance(ref, dict) else str(ref)
        if name and name not in names:
            names.append(name)
    return names


def cap_result(result: dict[str, Any], max_bytes: int = MAX_RESULT_BYTES) -> dict[str, Any]:
    """Keeps a tool result under `max_bytes` of JSON, trimming decompiled code first."""
    if len(json.dumps(result)) <= max_bytes:
        return result
    capped = dict(result)
    if isinstance(capped.get("decompiled"), str):
        overflow = len(json.dumps(capped)) - max_bytes
        code = capped["decompiled"]
        capped["decompiled"] = code[: max(len(code) - overflow - 200, 0)]
        capped["decompiled_truncated"] = True
        if len(json.dumps(capped)) <= max_bytes:
            return capped
    text = json.dumps(capped)[: max_bytes - 200]
    return {"truncated": True, "partial_json": text}


class FactsIndex:
    """Lookup tables over a facts document (as written to <target>_facts.json)."""

    def __init__(self, facts: dict[str, Any]) -> None:
        self.facts = facts
        self.functions: list[dict[str, Any]] = facts.get("functions", [])
        self.function_by_name = {f["name"]: f for f in self.functions if f.get("name")}
        self.function_by_bare_name = {_bare(f["name"]): f for f in self.functions if f.get("name")}
        self.function_by_address = {normalize_address(f["address"]): f for f in self.functions if f.get("address")}
        self.strings_by_address = {normalize_address(s["address"]): s for s in facts.get("strings", [])}
        self.globals_by_address = {normalize_address(g["address"]): g for g in facts.get("globals", [])}
        self.types_by_name = {t["name"]: t for t in facts.get("data_types", []) if t.get("name")}
        self.findings_by_function: dict[str, list[dict[str, Any]]] = {}
        for finding in facts.get("syscall_findings", []):
            self.findings_by_function.setdefault(finding.get("function"), []).append(finding)

        # Every address the facts mention: entries, instructions inside functions, call sites, xrefs, data.
        self.known_addresses = set(self.function_by_address) | set(self.strings_by_address) | set(self.globals_by_address)
        for fn in self.functions:
            for site in fn.get("callsites", []):
                self.known_addresses.add(normalize_address(site.get("at")))
        for item in list(facts.get("strings", [])) + list(facts.get("globals", [])):
            for ref in item.get("referenced_by", []):
                if isinstance(ref, dict) and ref.get("at"):
                    self.known_addresses.add(normalize_address(ref["at"]))
        self._function_ranges = []
        for fn in self.functions:
            try:
                start = int(normalize_address(fn["address"]).split(":")[-1], 16)
                self._function_ranges.append((start, start + max(int(fn.get("size") or 0), 1)))
            except (KeyError, ValueError):
                continue

    # -- resolution -------------------------------------------------------

    def find_function(self, name_or_address: str) -> dict[str, Any] | None:
        key = str(name_or_address or "").strip()
        return (
            self.function_by_name.get(key)
            or self.function_by_bare_name.get(_bare(key))
            or self.function_by_address.get(normalize_address(key))
        )

    def is_known_address(self, address: Any) -> bool:
        normalized = normalize_address(address)
        if normalized in self.known_addresses:
            return True
        try:
            value = int(normalized.split(":")[-1], 16)
        except ValueError:
            return False
        return any(start <= value < end for start, end in self._function_ranges)

    # -- tools ------------------------------------------------------------

    def get_function(self, name_or_address: str) -> dict[str, Any]:
        fn = self.find_function(name_or_address)
        if fn is None:
            names = [f["name"] for f in self.functions if f.get("name")]
            return {
                "error": f"No function named or at '{name_or_address}'.",
                "suggestions": difflib.get_close_matches(str(name_or_address), names, n=10, cutoff=0.4),
            }
        result = {key: fn.get(key) for key in (
            "name", "address", "size", "is_thunk", "signature", "calling_convention", "callers", "callees", "callsites",
        )}
        result["syscall_findings"] = [
            {k: f.get(k) for k in ("name", "severity", "callsite_address", "arguments", "code")}
            for f in self.findings_by_function.get(fn.get("name"), [])
        ]
        result["decompiled"] = fn.get("decompiled")
        return cap_result(result)

    def get_references(self, address: str) -> dict[str, Any]:
        normalized = normalize_address(address)
        if normalized in self.strings_by_address:
            s = self.strings_by_address[normalized]
            return cap_result({
                "kind": "string",
                "address": s.get("address"),
                "value": str(s.get("value", ""))[:MAX_STRING_VALUE],
                "origin": s.get("origin"),
                "referenced_by": s.get("referenced_by", []),
            })
        if normalized in self.globals_by_address:
            g = self.globals_by_address[normalized]
            return cap_result({
                "kind": "global",
                **{k: g.get(k) for k in ("address", "label", "type", "size", "section", "points_to", "origin")},
                "referenced_by": g.get("referenced_by", []),
            })
        fn = self.function_by_address.get(normalized)
        if fn is not None:
            call_sites = [
                {"function": caller.get("name"), "at": site.get("at")}
                for caller in self.functions
                for site in caller.get("callsites", [])
                if site.get("to") == fn.get("name")
            ]
            return cap_result({"kind": "function", "name": fn.get("name"), "address": fn.get("address"),
                               "called_from": call_sites})
        return {"error": f"Nothing known at address '{address}'."}

    def search_strings(self, query: str) -> dict[str, Any]:
        needle = str(query or "").lower()
        if not needle:
            return {"error": "Empty query."}
        hits = [s for s in self.facts.get("strings", []) if needle in str(s.get("value", "")).lower()]
        return cap_result({
            "query": query,
            "total_matches": len(hits),
            "matches": [
                {
                    "address": s.get("address"),
                    "value": str(s.get("value", ""))[:MAX_STRING_VALUE],
                    "section": s.get("section"),
                    "origin": s.get("origin"),
                    "referenced_by": _ref_names(s.get("referenced_by", [])),
                }
                for s in hits[:MAX_STRING_HITS]
            ],
        })

    def get_data_type(self, name: str) -> dict[str, Any]:
        data_type = self.types_by_name.get(str(name or "").strip())
        if data_type is None:
            return {
                "error": f"No data type named '{name}'.",
                "suggestions": difflib.get_close_matches(str(name), list(self.types_by_name), n=10, cutoff=0.4),
            }
        return cap_result(dict(data_type))

    def run_tool(self, name: str, args: dict[str, Any]) -> dict[str, Any]:
        tools: dict[str, Callable[..., dict[str, Any]]] = {
            "get_function": self.get_function,
            "get_references": self.get_references,
            "search_strings": self.search_strings,
            "get_data_type": self.get_data_type,
        }
        tool = tools.get(name)
        if tool is None:
            return {"error": f"Unknown tool '{name}'."}
        try:
            return tool(**(args or {}))
        except TypeError as e:
            return {"error": f"Bad arguments for {name}: {e}"}
