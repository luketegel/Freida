"""PyGhidra Context Collector.

Loads the target in-process with PyGhidra (headless, no GUI), runs Ghidra
auto-analysis, and extracts plain-Python facts about the program: metadata,
memory map, imports, exports, functions with signatures and callsites,
decompiled C, strings and global data with cross-references, and the data
types (structs, unions, enums, typedefs) the program actually uses.

The collector exposes the same query interface as GhidraMCPClient so the
orchestrator can drive either backend through one code path.
"""

from __future__ import annotations

import logging
import os
import tempfile
import warnings
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from freida.binary_insights import shannon_entropy

logger = logging.getLogger("freida.pyghidra_collector")

MAX_XREFS_PER_ITEM = 50
MAX_VALUE_PREVIEW = 120
MAX_ENTROPY_BLOCK_BYTES = 64 * 1024 * 1024

# Checked in order against the Ghidra class name (e.g. StructureDB, PointerTypedef, TypedefDB).
TYPE_KIND_MARKERS = (
    ("Typedef", "typedef"),
    ("Pointer", "pointer"),
    ("Array", "array"),
    ("Union", "union"),
    ("Structure", "struct"),
    ("Enum", "enum"),
    ("FunctionDefinition", "function"),
)
RECORDED_TYPE_KINDS = {"struct", "union", "enum", "typedef"}

class BackendUnavailableError(RuntimeError):
    """Raised when Ghidra or PyGhidra cannot be located or started."""
    pass


def _iter_java(java_iterable: Any) -> Iterable[Any]:
    """Iterates a Java Iterator/Iterable without relying on JPype customizers."""
    it = java_iterable.iterator() if hasattr(java_iterable, "iterator") else java_iterable
    while it.hasNext():
        yield it.next()


def _type_kind(dt: Any) -> str:
    class_name = str(dt.getClass().getSimpleName())
    for marker, kind in TYPE_KIND_MARKERS:
        if marker in class_name:
            return kind
    return "builtin"


def _serialize_type(dt: Any, kind: str) -> dict[str, Any]:
    item: dict[str, Any] = {
        "name": str(dt.getName()),
        "path": str(dt.getPathName()),
        "kind": kind,
        "size": int(dt.getLength()),
    }
    archive = dt.getSourceArchive()
    item["source_archive"] = str(archive.getName()) if archive is not None else None

    if kind in ("struct", "union"):
        components = dt.getDefinedComponents() if hasattr(dt, "getDefinedComponents") else dt.getComponents()
        item["fields"] = [
            {
                "offset": int(c.getOffset()),
                "name": str(c.getFieldName()) if c.getFieldName() is not None else None,
                "type": str(c.getDataType().getName()),
                "size": int(c.getLength()),
            }
            for c in list(components)
        ]
    elif kind == "enum":
        item["values"] = {str(n): int(dt.getValue(n)) for n in list(dt.getNames())}
    elif kind == "typedef":
        base = dt.getBaseDataType()
        item["base_type"] = str(base.getName()) if base is not None else None
    return item


class UsedTypeCollector:
    """Records the composite, enum and typedef types a program actually uses, and who uses them."""

    def __init__(self, max_types: int = 500) -> None:
        self.max_types = max_types
        self.truncated = False
        self._entries: dict[str, dict[str, Any]] = {}

    def add(self, dt: Any, user: str | None = None, _depth: int = 0) -> None:
        if dt is None or _depth > 8:
            return
        kind = _type_kind(dt)
        if kind in ("pointer", "array"):
            self.add(dt.getDataType(), user, _depth + 1)
            return
        if kind not in RECORDED_TYPE_KINDS:
            return

        path = str(dt.getPathName())
        entry = self._entries.get(path)
        if entry is None:
            if len(self._entries) >= self.max_types:
                self.truncated = True
                return
            entry = {"dt": dt, "kind": kind, "used_by": set()}
            self._entries[path] = entry
            # Follow nested types the first time a type is seen.
            if kind == "typedef":
                self.add(dt.getBaseDataType(), None, _depth + 1)
            elif kind in ("struct", "union"):
                for component in list(dt.getComponents()):
                    self.add(component.getDataType(), None, _depth + 1)
        if user:
            entry["used_by"].add(user)

    def serialize(self) -> list[dict[str, Any]]:
        types = []
        for path, entry in self._entries.items():
            try:
                item = _serialize_type(entry["dt"], entry["kind"])
            except Exception as e:
                logger.debug("Could not serialize data type %s: %s", path, e)
                continue
            item["used_by"] = sorted(entry["used_by"])
            types.append(item)
        return types


class PyGhidraCollector:
    """Collects program facts from Ghidra in-process via PyGhidra."""

    def __init__(
        self,
        target_path: str | Path,
        ghidra_install_dir: str | None = None,
        project_dir: Path | None = None,
        max_functions: int | None = None,
        decompile_timeout: int = 60,
        max_strings: int | None = None,
        max_globals: int | None = None,
        max_types: int = 500,
    ) -> None:
        self.target_path = Path(target_path).resolve()
        self.ghidra_install_dir = ghidra_install_dir or os.environ.get("GHIDRA_INSTALL_DIR") or ""
        self.project_dir = Path(project_dir) if project_dir else None
        self.max_functions = max_functions
        self.decompile_timeout = decompile_timeout
        self.max_strings = max_strings
        self.max_globals = max_globals
        self.max_types = max_types

        self.facts: dict[str, Any] = {}
        self._decompiled_by_address: dict[str, str] = {}
        self._decompiled_by_name: dict[str, str] = {}

    # ------------------------------------------------------------------
    # Backend interface (mirrors GhidraMCPClient)
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Runs the full collection pass."""
        self.collect()

    def close(self) -> None:
        """Nothing to release; projects are cleaned up inside collect()."""
        pass

    def get_program_info(self) -> dict[str, Any]:
        return self.facts.get("program", {})

    def list_imports(self) -> list[dict[str, Any]]:
        return self.facts.get("imports", [])

    def list_functions(self, limit: int = 100) -> list[dict[str, Any]]:
        return [
            {"name": f["name"], "address": f["address"], "callsites": f.get("callsites", [])}
            for f in self.facts.get("functions", [])
        ]

    def decompile_function(self, function_name: str, address: str | None = None) -> str | None:
        if address and address in self._decompiled_by_address:
            return self._decompiled_by_address[address]
        return self._decompiled_by_name.get(function_name)

    def load_facts(self, facts: dict[str, Any]) -> None:
        """Installs pre-collected facts and indexes decompiled code for lookup."""
        self.facts = facts
        self._decompiled_by_address = {}
        self._decompiled_by_name = {}
        for fn in facts.get("functions", []):
            code = fn.get("decompiled")
            if not code:
                continue
            if fn.get("address"):
                self._decompiled_by_address[fn["address"]] = code
            self._decompiled_by_name.setdefault(fn["name"], code)

    # ------------------------------------------------------------------
    # Collection
    # ------------------------------------------------------------------

    def collect(self) -> dict[str, Any]:
        """Loads the target with PyGhidra and gathers facts about the program."""
        pyghidra = self._start_pyghidra()

        with tempfile.TemporaryDirectory(prefix="freida_") as tmp:
            project_location = self.project_dir or (Path(tmp) / "project")
            project_location.mkdir(parents=True, exist_ok=True)
            logger.info("Loading %s into Ghidra (headless, PyGhidra)...", self.target_path.name)
            facts = self._collect_program(pyghidra, project_location)

        facts["limits"] = {
            "max_functions": self.max_functions,
            "functions_collected": len(facts["functions"]),
            "functions_total": facts.pop("total_functions"),
            "max_strings": self.max_strings,
            "max_globals": self.max_globals,
            "max_types": self.max_types,
            "data_types_truncated": facts.pop("data_types_truncated", False),
        }
        self.load_facts(facts)
        return facts

    def _start_pyghidra(self) -> Any:
        if not self.ghidra_install_dir:
            raise BackendUnavailableError(
                "Ghidra installation not found. Set GHIDRA_INSTALL_DIR or pass --ghidra-dir."
            )
        if not Path(self.ghidra_install_dir).is_dir():
            raise BackendUnavailableError(f"Ghidra installation directory does not exist: {self.ghidra_install_dir}")

        try:
            import pyghidra  # type: ignore[import-not-found]
        except ImportError as e:
            raise BackendUnavailableError(
                "PyGhidra is not installed. Install it with "
                "`pip install -e '.[ghidra]'` or from "
                "$GHIDRA_INSTALL_DIR/Ghidra/Features/PyGhidra/pypkg/dist."
            ) from e

        started = getattr(pyghidra, "started", None)
        if not (callable(started) and started()):
            pyghidra.start(install_dir=Path(self.ghidra_install_dir))
        return pyghidra

    def _collect_program(self, pyghidra: Any, project_location: Path) -> dict[str, Any]:
        with warnings.catch_warnings():
            # open_program is deprecated in newer PyGhidra releases but remains the
            # simplest supported way to load-and-analyze a single file.
            warnings.simplefilter("ignore", DeprecationWarning)
            with pyghidra.open_program(
                str(self.target_path),
                project_location=str(project_location),
                project_name=f"freida_{self.target_path.stem}",
                analyze=True,
            ) as flat_api:
                program = flat_api.getCurrentProgram()
                return self._extract_program_facts(program)

    def _extract_program_facts(self, program: Any) -> dict[str, Any]:
        from ghidra.app.decompiler import DecompInterface  # type: ignore[import-not-found]
        from ghidra.util.task import ConsoleTaskMonitor  # type: ignore[import-not-found]

        monitor = ConsoleTaskMonitor()
        symbol_table = program.getSymbolTable()
        function_manager = program.getFunctionManager()
        listing = program.getListing()

        entry_points = [str(addr) for addr in _iter_java(symbol_table.getExternalEntryPointIterator())]

        info = {
            "name": str(program.getName()),
            "language_id": str(program.getLanguageID().getIdAsString()),
            "compiler_spec_id": str(program.getCompilerSpec().getCompilerSpecID().getIdAsString()),
            "image_base": str(program.getImageBase()),
            "format": str(program.getExecutableFormat()),
            "pointer_size": int(program.getDefaultPointerSize()),
            "big_endian": bool(program.getLanguage().isBigEndian()),
            "entry_points": entry_points,
        }

        imports = []
        for sym in _iter_java(symbol_table.getExternalSymbols()):
            parent = sym.getParentNamespace()
            imports.append({
                "name": str(sym.getName()),
                "library": str(parent.getName()) if parent is not None else None,
                "address": str(sym.getAddress()),
            })

        exports = []
        for addr_str in entry_points:
            addr = program.getAddressFactory().getAddress(addr_str)
            sym = symbol_table.getPrimarySymbol(addr) if addr is not None else None
            exports.append({"name": str(sym.getName()) if sym else None, "address": addr_str})

        types = UsedTypeCollector(self.max_types)
        decomp = DecompInterface()
        decomp.openProgram(program)
        functions: list[dict[str, Any]] = []
        total_functions = 0
        try:
            for func in _iter_java(function_manager.getFunctions(True)):
                total_functions += 1
                if self.max_functions is not None and len(functions) >= self.max_functions:
                    continue
                functions.append(self._extract_function(func, function_manager, listing, decomp, monitor, types))
        finally:
            decomp.dispose()

        strings = self._extract_strings(program)
        global_data = self._extract_globals(program, types)

        return {
            "program": info,
            "program_metadata": self._extract_program_metadata(program),
            "memory_map": self._extract_memory_map(program),
            "imports": imports,
            "exports": exports,
            "functions": functions,
            "total_functions": total_functions,
            "strings": strings,
            "globals": global_data,
            "data_types": types.serialize(),
            "data_types_truncated": types.truncated,
        }

    def _extract_function(
        self,
        func: Any,
        function_manager: Any,
        listing: Any,
        decomp: Any,
        monitor: Any,
        types: UsedTypeCollector | None = None,
    ) -> dict[str, Any]:
        name = str(func.getName(True))
        callsites = []
        for instr in _iter_java(listing.getInstructions(func.getBody(), True)):
            if not instr.getFlowType().isCall():
                continue
            targets = list(instr.getFlows()) or [
                ref.getToAddress() for ref in instr.getReferencesFrom() if ref.getReferenceType().isCall()
            ]
            for target in targets:
                callee = function_manager.getFunctionAt(target)
                callsites.append({
                    "to": str(callee.getName(True)) if callee else str(target),
                    "at": str(instr.getAddress()),
                })

        callees = sorted({str(f.getName(True)) for f in _iter_java(func.getCalledFunctions(monitor))})

        signature = calling_convention = None
        try:
            signature = str(func.getPrototypeString(False, False))
            calling_convention = str(func.getCallingConventionName())
        except Exception as e:
            logger.debug("Could not read signature of %s: %s", name, e)

        if types is not None:
            try:
                types.add(func.getReturnType(), name)
                for param in list(func.getParameters()):
                    types.add(param.getDataType(), name)
                for var in list(func.getLocalVariables()):
                    types.add(var.getDataType(), name)
            except Exception as e:
                logger.debug("Could not read variable types of %s: %s", name, e)

        is_thunk = bool(func.isThunk())
        decompiled = None
        if not is_thunk:
            results = decomp.decompileFunction(func, self.decompile_timeout, monitor)
            if results is not None and results.decompileCompleted():
                decompiled = str(results.getDecompiledFunction().getC())
                if types is not None:
                    self._add_decompiler_types(results, types, name)
            else:
                logger.debug("Decompilation failed for %s", func.getName())

        return {
            "name": name,
            "address": str(func.getEntryPoint()),
            "size": int(func.getBody().getNumAddresses()),
            "is_thunk": is_thunk,
            "signature": signature,
            "calling_convention": calling_convention,
            "callees": callees,
            "callsites": callsites,
            "decompiled": decompiled,
        }

    @staticmethod
    def _add_decompiler_types(results: Any, types: UsedTypeCollector, user: str) -> None:
        """Adds types the decompiler inferred for locals (e.g. `sockaddr` propagated from a call)."""
        try:
            high_function = results.getHighFunction()
            if high_function is not None:
                for symbol in _iter_java(high_function.getLocalSymbolMap().getSymbols()):
                    types.add(symbol.getDataType(), user)
        except Exception as e:
            logger.debug("Could not read decompiler types of %s: %s", user, e)

    def _referencing_functions(self, program: Any, address: Any, pointer_hops: int = 1) -> list[dict[str, Any]]:
        """Functions that reference an address, following pointers stored in data (e.g. `PTR_s__bin_ls`)."""
        results: list[dict[str, Any]] = []
        try:
            reference_manager = program.getReferenceManager()
            function_manager = program.getFunctionManager()
            listing = program.getListing()
            seen: set[Any] = set()

            def visit(target: Any, hops: int) -> None:
                for ref in _iter_java(reference_manager.getReferencesTo(target)):
                    if len(results) >= MAX_XREFS_PER_ITEM:
                        return
                    source = ref.getFromAddress()
                    func = function_manager.getFunctionContaining(source)
                    if func is not None:
                        key = (str(func.getName(True)), str(source))
                        if key not in seen:
                            seen.add(key)
                            results.append({"function": key[0], "at": key[1], "ref_type": str(ref.getReferenceType())})
                    elif hops > 0:
                        data = listing.getDataContaining(source)
                        if data is not None and data.isPointer():
                            visit(data.getAddress(), hops - 1)

            visit(address, pointer_hops)
        except Exception as e:
            logger.debug("Could not resolve references to %s: %s", address, e)
        return results

    @staticmethod
    def _section_of(program: Any, address: Any) -> str | None:
        try:
            block = program.getMemory().getBlock(address)
            return str(block.getName()) if block is not None else None
        except Exception:
            return None

    @staticmethod
    def _type_name(data: Any) -> str | None:
        try:
            return str(data.getDataType().getName())
        except Exception:
            return None

    def _extract_strings(self, program: Any) -> list[dict[str, Any]]:
        """Collects all defined strings with section and referencing functions; failures are not fatal."""
        strings: list[dict[str, Any]] = []
        try:
            for data in self._iter_defined_strings(program):
                if self.max_strings is not None and len(strings) >= self.max_strings:
                    break
                value = data.getValue()
                if value is None:
                    continue
                address = data.getAddress()
                referenced_by = self._referencing_functions(program, address)
                strings.append({
                    "address": str(address),
                    "value": str(value),
                    "length": len(str(value)),
                    "encoding": self._type_name(data),
                    "section": self._section_of(program, address),
                    "referenced_by": referenced_by,
                    "referenced": bool(referenced_by),
                })
        except Exception as e:
            logger.warning("Could not extract strings from %s: %s", self.target_path.name, e)
        return strings

    def _extract_globals(self, program: Any, types: UsedTypeCollector | None = None) -> list[dict[str, Any]]:
        """Collects non-string defined data (global variables, pointers, tables) with cross-references."""
        global_data: list[dict[str, Any]] = []
        try:
            symbol_table = program.getSymbolTable()
            for data in _iter_java(program.getListing().getDefinedData(True)):
                if data.hasStringValue():
                    continue
                if self.max_globals is not None and len(global_data) >= self.max_globals:
                    break
                address = data.getAddress()
                label = data.getLabel()
                entry: dict[str, Any] = {
                    "address": str(address),
                    "label": str(label) if label is not None else None,
                    "type": self._type_name(data),
                    "size": int(data.getLength()),
                    "section": self._section_of(program, address),
                    "value_preview": str(data.getDefaultValueRepresentation() or "")[:MAX_VALUE_PREVIEW],
                }
                if data.isPointer():
                    target = data.getValue()
                    if target is not None:
                        symbol = symbol_table.getPrimarySymbol(target)
                        entry["points_to"] = str(symbol.getName(True)) if symbol is not None else str(target)
                entry["referenced_by"] = self._referencing_functions(program, address)
                global_data.append(entry)
                if types is not None:
                    types.add(data.getDataType(), f"data:{entry['label'] or entry['address']}")
        except Exception as e:
            logger.warning("Could not extract global data from %s: %s", self.target_path.name, e)
        return global_data

    def _extract_memory_map(self, program: Any) -> list[dict[str, Any]]:
        """Memory blocks with permissions and, for initialized blocks, byte entropy."""
        blocks: list[dict[str, Any]] = []
        try:
            for block in list(program.getMemory().getBlocks()):
                size = int(block.getSize())
                entry: dict[str, Any] = {
                    "name": str(block.getName()),
                    "start": str(block.getStart()),
                    "end": str(block.getEnd()),
                    "size": size,
                    "permissions": ("r" if block.isRead() else "-")
                    + ("w" if block.isWrite() else "-")
                    + ("x" if block.isExecute() else "-"),
                    "initialized": bool(block.isInitialized()),
                    "type": str(block.getType()),
                }
                if entry["initialized"] and 0 < size <= MAX_ENTROPY_BLOCK_BYTES:
                    content = self._read_block_bytes(block)
                    if content is not None:
                        entry["entropy"] = round(shannon_entropy(content), 3)
                blocks.append(entry)
        except Exception as e:
            logger.warning("Could not extract memory map from %s: %s", self.target_path.name, e)
        return blocks

    @staticmethod
    def _read_block_bytes(block: Any) -> bytes | None:
        try:
            import jpype  # type: ignore[import-not-found]

            buffer = jpype.JArray(jpype.JByte)(int(block.getSize()))
            block.getBytes(block.getStart(), buffer)
            return memoryview(buffer).tobytes()
        except Exception as e:
            logger.debug("Could not read bytes of block %s: %s", block.getName(), e)
            return None

    def _extract_program_metadata(self, program: Any) -> dict[str, str | None]:
        """Ghidra's 'Program Information' options (compiler, format details, libraries) and source file info."""
        metadata: dict[str, str | None] = {}
        try:
            options = program.getOptions("Program Information")
            for option_name in _iter_java(options.getOptionNames()):
                value = options.getObject(option_name, None)
                metadata[str(option_name)] = str(value) if value is not None else None
        except Exception as e:
            logger.warning("Could not read program information from %s: %s", self.target_path.name, e)

        for key, getter in (
            ("executable_path", "getExecutablePath"),
            ("executable_md5", "getExecutableMD5"),
            ("executable_sha256", "getExecutableSHA256"),
        ):
            try:
                value = getattr(program, getter)()
                metadata[key] = str(value) if value is not None else None
            except Exception:
                pass
        return metadata

    @staticmethod
    def _iter_defined_strings(program: Any) -> Iterable[Any]:
        try:
            # Ghidra 11+; DefinedDataIterator.definedStrings() no longer exists in Ghidra 12.
            from ghidra.program.util import DefinedStringIterator  # type: ignore[import-not-found]
        except ImportError:
            return (
                data
                for data in _iter_java(program.getListing().getDefinedData(True))
                if data.hasStringValue()
            )
        return _iter_java(DefinedStringIterator.forProgram(program))
