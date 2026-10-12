"""Binary Insights.

Pure-Python analysis over collected facts and the target file itself:
Shannon entropy, indicators extracted from strings (URLs, IPs, paths,
registry keys, commands), executable hardening signals parsed from
ELF / Mach-O / PE headers, the reverse call graph, and tagging of
file-format metadata (loader structures, symbol tables) versus program content.

Nothing here needs Ghidra, so every function can be unit-tested directly.
"""

from __future__ import annotations

import bisect
import collections
import math
import re
import struct
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Union

# ---------------------------------------------------------------------------
# Entropy
# ---------------------------------------------------------------------------


def shannon_entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte (0.0 for empty or uniform data, up to 8.0)."""
    if not data:
        return 0.0
    counts = collections.Counter(data)
    total = len(data)
    return abs(-sum((c / total) * math.log2(c / total) for c in counts.values()))


# ---------------------------------------------------------------------------
# Indicators
# ---------------------------------------------------------------------------

_TLDS = (
    "com|net|org|io|co|me|info|biz|xyz|top|online|site|club|app|dev|gov|edu|mil|"
    "ru|cn|su|tk|cc|uk|de|fr|jp|kr|br|in|us|eu|nl|it|es|pl|ir|onion"
)

INDICATOR_PATTERNS: Dict[str, "re.Pattern[str]"] = {
    "url": re.compile(r"\b(?:https?|ftp|wss?)://[^\s\"'<>]+", re.IGNORECASE),
    "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    "ipv4": re.compile(r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d.])"),
    "domain": re.compile(rf"\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+(?:{_TLDS})\b", re.IGNORECASE),
    "unix_path": re.compile(r"(?<![\w./-])/(?:[\w.+-]+/)+[\w.+-]+"),
    "windows_path": re.compile(r"\b[A-Za-z]:\\(?:[^\\/:*?\"<>|\r\n]+\\)*[^\\/:*?\"<>|\r\n]*|\\\\[\w.-]+\\[^\s\"'<>|]+"),
    "registry_key": re.compile(
        r"\b(?:HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|CURRENT_CONFIG)|HKLM|HKCU|HKCR|HKU)\\[^\s\"']+"
        r"|\bSOFTWARE\\[^\s\"']+",
        re.IGNORECASE,
    ),
}

COMMAND_MARKERS = (
    "/bin/sh", "/bin/bash", "/bin/zsh", "sh -c", "bash -c", "cmd.exe", "cmd /c",
    "powershell", "pwsh", "wget ", "curl ", "chmod +x", "nc -e", "rm -rf",
)

MAX_INDICATOR_LENGTH = 200


def _function_names(referenced_by: Iterable[Any]) -> List[str]:
    names = {r["function"] if isinstance(r, dict) else str(r) for r in referenced_by or []}
    return sorted(n for n in names if n)


def extract_indicators(strings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Pulls network, filesystem, registry and command indicators out of collected strings."""
    indicators: List[Dict[str, Any]] = []
    seen = set()

    def add(kind: str, value: str, s: Dict[str, Any]) -> None:
        value = value.strip()[:MAX_INDICATOR_LENGTH]
        key = (kind, value, s.get("address"))
        if key in seen:
            return
        seen.add(key)
        indicators.append({
            "kind": kind,
            "value": value,
            "string_address": s.get("address"),
            "referenced_by": _function_names(s.get("referenced_by", [])),
            "origin": s.get("origin", "program"),
        })

    for s in strings:
        text = str(s.get("value") or "")
        if not text:
            continue
        for kind, pattern in INDICATOR_PATTERNS.items():
            for match in pattern.finditer(text):
                add(kind, match.group(0), s)
        lowered = text.lower()
        if any(marker in lowered for marker in COMMAND_MARKERS):
            add("command", text.strip(), s)

    return indicators


# ---------------------------------------------------------------------------
# File-format metadata vs. program content
# ---------------------------------------------------------------------------

# Ghidra data type categories created by the executable loaders.
LOADER_TYPE_CATEGORIES = {"MachO", "Mach-O", "ELF", "PE", "COFF"}

# Blocks holding loader / linker / unwind metadata rather than program data.
METADATA_SECTIONS = {
    # Mach-O
    "__LINKEDIT", "__unwind_info", "__eh_frame",
    # ELF
    "_elfHeader", "_elfProgramHeaders", "_elfSectionHeaders", ".dynsym", ".dynstr", ".symtab", ".strtab",
    ".shstrtab", ".gnu.hash", ".hash", ".gnu.version", ".gnu.version_r", ".gnu.version_d", ".rela.dyn",
    ".rela.plt", ".rel.dyn", ".rel.plt", ".note.gnu.build-id", ".note.ABI-tag", ".note.gnu.property",
    ".eh_frame", ".eh_frame_hdr", ".gnu_debuglink", ".comment",
    # PE
    "Headers", ".reloc",
}


def _int_address(address: Any) -> Optional[int]:
    try:
        return int(str(address).split(":")[-1], 16)
    except ValueError:
        return None


def _type_category(path: Optional[str]) -> str:
    parts = str(path or "").strip("/").split("/")
    return parts[0] if len(parts) > 1 else ""


def classify_origins(facts: Dict[str, Any]) -> Dict[str, int]:
    """Tags data types, globals and strings with origin "file_format" or "program".

    File-format items describe the executable's own layout (load commands, symbol
    and string tables, fixups) and are not used by any code; everything a function
    references counts as program content. Returns per-section file-format counts.
    """
    loader_type_names = set()
    for t in facts.get("data_types", []):
        is_loader_type = _type_category(t.get("path")) in LOADER_TYPE_CATEGORIES
        if is_loader_type:
            loader_type_names.add(t.get("name"))
        function_users = [u for u in t.get("used_by", []) if not str(u).startswith("data:")]
        t["origin"] = "file_format" if is_loader_type and not function_users else "program"

    ranges = []
    for g in facts.get("globals", []):
        is_metadata = not g.get("referenced_by") and (
            g.get("type") in loader_type_names or g.get("section") in METADATA_SECTIONS
        )
        g["origin"] = "file_format" if is_metadata else "program"
        start = _int_address(g.get("address"))
        if is_metadata and start is not None:
            ranges.append((start, start + max(int(g.get("size") or 0), 1)))
    ranges.sort()
    starts = [r[0] for r in ranges]

    # Blocks holding only file-format data (e.g. the Mach-O load-command header) are metadata as a whole,
    # which also covers strings stored just past a structure, like a dylib_command's library path.
    blocks = [(_int_address(b.get("start")), _int_address(b.get("end"))) for b in facts.get("memory_map", [])]

    def block_of(address: Optional[int]) -> Optional[int]:
        if address is None:
            return None
        for index, (start, end) in enumerate(blocks):
            if start is not None and end is not None and start <= address <= end:
                return index
        return None

    blocks_with_metadata = {block_of(_int_address(g.get("address"))) for g in facts.get("globals", [])
                            if g["origin"] == "file_format"}
    blocks_with_program = {block_of(_int_address(g.get("address"))) for g in facts.get("globals", [])
                           if g["origin"] == "program"}
    blocks_with_program |= {block_of(_int_address(f.get("address"))) for f in facts.get("functions", [])}
    metadata_blocks = (blocks_with_metadata - blocks_with_program) - {None}

    for s in facts.get("strings", []):
        inside_metadata = False
        address = _int_address(s.get("address"))
        if address is not None and ranges:
            i = bisect.bisect_right(starts, address) - 1
            inside_metadata = i >= 0 and address < ranges[i][1]
        in_metadata_block = block_of(address) in metadata_blocks
        is_metadata = not s.get("referenced_by") and (
            inside_metadata or in_metadata_block or s.get("section") in METADATA_SECTIONS
        )
        s["origin"] = "file_format" if is_metadata else "program"

    return {
        section: sum(1 for item in facts.get(section, []) if item.get("origin") == "file_format")
        for section in ("strings", "globals", "data_types")
    }


# ---------------------------------------------------------------------------
# Call graph
# ---------------------------------------------------------------------------


def callers_by_function(functions: List[Dict[str, Any]]) -> Dict[str, List[str]]:
    """Reverse call graph: callee name -> sorted names of functions that call it."""
    callers: Dict[str, set] = collections.defaultdict(set)
    for fn in functions:
        for site in fn.get("callsites") or []:
            if site.get("to"):
                callers[site["to"]].add(fn.get("name"))
    return {callee: sorted(c for c in names if c) for callee, names in callers.items()}


# ---------------------------------------------------------------------------
# Hardening
# ---------------------------------------------------------------------------

# ELF
PT_DYNAMIC = 2
PT_GNU_STACK = 0x6474E551
PT_GNU_RELRO = 0x6474E552
PF_X = 0x1
DT_BIND_NOW = 24
DT_FLAGS = 30
DT_FLAGS_1 = 0x6FFFFFFB
DF_BIND_NOW = 0x8
DF_1_NOW = 0x1

# Mach-O
MH_ALLOW_STACK_EXECUTION = 0x20000
MH_PIE = 0x200000
MH_NO_HEAP_EXECUTION = 0x1000000

# PE
IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA = 0x0020
IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040
IMAGE_DLLCHARACTERISTICS_NX_COMPAT = 0x0100
IMAGE_DLLCHARACTERISTICS_GUARD_CF = 0x4000

STACK_CANARY_SYMBOLS = {"stack_chk_fail", "stack_chk_guard", "security_check_cookie", "security_cookie"}


def _elf_hardening(data: bytes) -> Dict[str, Any]:
    is64 = data[4] == 2
    endian = "<" if data[5] == 1 else ">"
    e_type = struct.unpack_from(endian + "H", data, 16)[0]

    if is64:
        e_phoff = struct.unpack_from(endian + "Q", data, 0x20)[0]
        e_phentsize, e_phnum = struct.unpack_from(endian + "HH", data, 0x36)
    else:
        e_phoff = struct.unpack_from(endian + "I", data, 0x1C)[0]
        e_phentsize, e_phnum = struct.unpack_from(endian + "HH", data, 0x2A)

    nx = False  # no PT_GNU_STACK means an executable stack
    has_relro = False
    dynamic = None
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        if off + e_phentsize > len(data):
            break
        p_type = struct.unpack_from(endian + "I", data, off)[0]
        if is64:
            p_flags = struct.unpack_from(endian + "I", data, off + 4)[0]
            p_offset, p_filesz = struct.unpack_from(endian + "Q", data, off + 8)[0], struct.unpack_from(endian + "Q", data, off + 32)[0]
        else:
            p_offset, p_filesz = struct.unpack_from(endian + "I", data, off + 4)[0], struct.unpack_from(endian + "I", data, off + 16)[0]
            p_flags = struct.unpack_from(endian + "I", data, off + 24)[0]
        if p_type == PT_GNU_STACK:
            nx = not (p_flags & PF_X)
        elif p_type == PT_GNU_RELRO:
            has_relro = True
        elif p_type == PT_DYNAMIC:
            dynamic = (p_offset, p_filesz)

    bind_now = False
    if dynamic:
        entry_fmt, entry_size = (endian + "qQ", 16) if is64 else (endian + "iI", 8)
        start, size = dynamic
        for off in range(start, min(start + size, len(data) - entry_size + 1), entry_size):
            tag, val = struct.unpack_from(entry_fmt, data, off)
            if tag == 0:
                break
            if tag == DT_BIND_NOW or (tag == DT_FLAGS and val & DF_BIND_NOW) or (tag == DT_FLAGS_1 and val & DF_1_NOW):
                bind_now = True

    return {
        "format": "ELF",
        "pie": e_type == 3,  # ET_DYN (PIE executable or shared object)
        "nx": nx,
        "relro": ("full" if bind_now else "partial") if has_relro else "none",
    }


def _macho_hardening(data: bytes) -> Dict[str, Any]:
    magic = data[:4]
    if magic == b"\xca\xfe\xba\xbe":
        # Universal binary: report the first architecture slice.
        nfat = struct.unpack_from(">I", data, 4)[0]
        if nfat == 0:
            return {"format": "Mach-O Universal"}
        slice_offset = struct.unpack_from(">I", data, 8 + 8)[0]
        result = _macho_hardening(data[slice_offset:])
        result["format"] = "Mach-O Universal"
        return result

    endian = "<" if magic in (b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe") else ">"
    flags = struct.unpack_from(endian + "I", data, 24)[0]
    return {
        "format": "Mach-O",
        "pie": bool(flags & MH_PIE),
        "nx": not (flags & MH_ALLOW_STACK_EXECUTION),
        "heap_nx": bool(flags & MH_NO_HEAP_EXECUTION),
        "relro": None,
    }


def _pe_hardening(data: bytes) -> Dict[str, Any]:
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        return {"format": "PE"}
    dll_characteristics = struct.unpack_from("<H", data, e_lfanew + 24 + 70)[0]
    return {
        "format": "PE",
        "pie": bool(dll_characteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE),
        "nx": bool(dll_characteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT),
        "high_entropy_aslr": bool(dll_characteristics & IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA),
        "control_flow_guard": bool(dll_characteristics & IMAGE_DLLCHARACTERISTICS_GUARD_CF),
        "relro": None,
    }


def header_hardening(target_path: Union[str, Path]) -> Dict[str, Any]:
    """Parses PIE / NX / RELRO style flags from the executable header; unknown values are None."""
    try:
        data = Path(target_path).read_bytes()
        if data[:4] == b"\x7fELF":
            return _elf_hardening(data)
        if data[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe",
                        b"\xca\xfe\xba\xbe"):
            return _macho_hardening(data)
        if data[:2] == b"MZ":
            return _pe_hardening(data)
    except (OSError, struct.error, IndexError) as e:
        return {"format": None, "pie": None, "nx": None, "relro": None, "error": str(e)}
    return {"format": None, "pie": None, "nx": None, "relro": None}


def hardening(target_path: Union[str, Path], facts: Dict[str, Any]) -> Dict[str, Any]:
    """Combines header flags with signals from Ghidra facts (canary, FORTIFY, RWX, stripped)."""
    result = header_hardening(target_path)

    symbol_names = [i.get("name") or "" for i in facts.get("imports", [])]
    symbol_names += [f.get("name") or "" for f in facts.get("functions", [])]
    bare = {name.split("::")[-1].lstrip("_") for name in symbol_names}

    result["stack_canary"] = bool(bare & STACK_CANARY_SYMBOLS)
    result["fortify_source"] = any(n.endswith("_chk") and n not in STACK_CANARY_SYMBOLS for n in bare)

    memory_map = facts.get("memory_map")
    result["rwx_sections"] = (
        [b["name"] for b in memory_map if b.get("permissions") == "rwx"] if memory_map is not None else None
    )

    own_functions = [f for f in facts.get("functions", []) if not f.get("is_thunk")]
    if own_functions:
        default_named = sum(1 for f in own_functions if str(f.get("name", "")).startswith("FUN_"))
        result["stripped"] = default_named / len(own_functions) > 0.5
    else:
        result["stripped"] = None
    return result
