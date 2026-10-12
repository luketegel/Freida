"""PyGhidra Context Collector.

Loads the target in-process with PyGhidra (headless, no GUI), runs Ghidra
auto-analysis, and extracts plain-Python facts about the program: metadata,
imports, exports, functions with callsites, decompiled C, and defined strings.

The collector exposes the same query interface as GhidraMCPClient so the
orchestrator can drive either backend through one code path.
"""

from __future__ import annotations

import logging
import os
import tempfile
import warnings
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Union

logger = logging.getLogger("ghidra_syscall_analyzer.pyghidra_collector")

class BackendUnavailableError(RuntimeError):
    """Raised when Ghidra or PyGhidra cannot be located or started."""
    pass


def _iter_java(java_iterable: Any) -> Iterable[Any]:
    """Iterates a Java Iterator/Iterable without relying on JPype customizers."""
    it = java_iterable.iterator() if hasattr(java_iterable, "iterator") else java_iterable
    while it.hasNext():
        yield it.next()


class PyGhidraCollector:
    """Collects program facts from Ghidra in-process via PyGhidra."""

    def __init__(
        self,
        target_path: Union[str, Path],
        ghidra_install_dir: Optional[str] = None,
        project_dir: Optional[Path] = None,
        max_functions: Optional[int] = None,
        decompile_timeout: int = 60,
        max_strings: int = 2000,
    ) -> None:
        self.target_path = Path(target_path).resolve()
        self.ghidra_install_dir = ghidra_install_dir or os.environ.get("GHIDRA_INSTALL_DIR") or ""
        self.project_dir = Path(project_dir) if project_dir else None
        self.max_functions = max_functions
        self.decompile_timeout = decompile_timeout
        self.max_strings = max_strings

        self.facts: Dict[str, Any] = {}
        self._decompiled_by_address: Dict[str, str] = {}
        self._decompiled_by_name: Dict[str, str] = {}

    # ------------------------------------------------------------------
    # Backend interface (mirrors GhidraMCPClient)
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Runs the full collection pass."""
        self.collect()

    def close(self) -> None:
        """Nothing to release; projects are cleaned up inside collect()."""
        pass

    def get_program_info(self) -> Dict[str, Any]:
        return self.facts.get("program", {})

    def list_imports(self) -> List[Dict[str, Any]]:
        return self.facts.get("imports", [])

    def list_functions(self, limit: int = 100) -> List[Dict[str, Any]]:
        return [
            {"name": f["name"], "address": f["address"], "callsites": f.get("callsites", [])}
            for f in self.facts.get("functions", [])
        ]

    def decompile_function(self, function_name: str, address: Optional[str] = None) -> Optional[str]:
        if address and address in self._decompiled_by_address:
            return self._decompiled_by_address[address]
        return self._decompiled_by_name.get(function_name)

    def load_facts(self, facts: Dict[str, Any]) -> None:
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

    def collect(self) -> Dict[str, Any]:
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

    def _collect_program(self, pyghidra: Any, project_location: Path) -> Dict[str, Any]:
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

    def _extract_program_facts(self, program: Any) -> Dict[str, Any]:
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

        decomp = DecompInterface()
        decomp.openProgram(program)
        functions: List[Dict[str, Any]] = []
        total_functions = 0
        try:
            for func in _iter_java(function_manager.getFunctions(True)):
                total_functions += 1
                if self.max_functions is not None and len(functions) >= self.max_functions:
                    continue
                functions.append(self._extract_function(func, function_manager, listing, decomp, monitor))
        finally:
            decomp.dispose()

        strings = self._extract_strings(program)

        return {
            "program": info,
            "imports": imports,
            "exports": exports,
            "functions": functions,
            "total_functions": total_functions,
            "strings": strings,
        }

    def _extract_function(
        self,
        func: Any,
        function_manager: Any,
        listing: Any,
        decomp: Any,
        monitor: Any,
    ) -> Dict[str, Any]:
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

        is_thunk = bool(func.isThunk())
        decompiled = None
        if not is_thunk:
            results = decomp.decompileFunction(func, self.decompile_timeout, monitor)
            if results is not None and results.decompileCompleted():
                decompiled = str(results.getDecompiledFunction().getC())
            else:
                logger.debug("Decompilation failed for %s", func.getName())

        return {
            "name": str(func.getName(True)),
            "address": str(func.getEntryPoint()),
            "size": int(func.getBody().getNumAddresses()),
            "is_thunk": is_thunk,
            "callees": callees,
            "callsites": callsites,
            "decompiled": decompiled,
        }

    def _extract_strings(self, program: Any) -> List[Dict[str, Any]]:
        """Collects defined strings; strings are supporting context, so failures are not fatal."""
        strings: List[Dict[str, Any]] = []
        try:
            for data in self._iter_defined_strings(program):
                if len(strings) >= self.max_strings:
                    break
                value = data.getValue()
                if value is None:
                    continue
                strings.append({"address": str(data.getAddress()), "value": str(value)})
        except Exception as e:
            logger.warning("Could not extract strings from %s: %s", self.target_path.name, e)
        return strings

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
