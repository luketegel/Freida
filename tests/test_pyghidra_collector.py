"""Tests for PyGhidraCollector: backend interface, archive handling, and live Ghidra integration."""

import os
import shutil
import subprocess
import sys
import tempfile
import types
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from ghidra_syscall_analyzer.pyghidra_collector import PyGhidraCollector, extract_class_files

SAMPLES = Path(__file__).resolve().parent.parent / "ghidra_syscall_analyzer" / "samples"

FAKE_FACTS = {
    "program": {"name": "sample", "language_id": "x86:LE:64:default", "entry_points": ["00101000"]},
    "imports": [{"name": "execve", "library": "libc.so.6", "address": "EXTERNAL:00000001"}],
    "exports": [{"name": "entry", "address": "00101000"}],
    "functions": [
        {"name": "main", "address": "00101100", "decompiled": "int main(void) {\n  execve(\"/bin/sh\",0,0);\n}"},
        {"name": "execve", "address": "00101030", "is_thunk": True, "decompiled": None},
    ],
    "strings": [{"address": "00102000", "value": "/bin/sh"}],
    "total_functions": 2,
}


class TestPyGhidraCollectorInterface(unittest.TestCase):

    def setUp(self) -> None:
        self.collector = PyGhidraCollector(target_path=__file__)
        self.collector.load_facts(FAKE_FACTS)

    def test_serves_program_info_and_imports(self) -> None:
        self.assertEqual(self.collector.get_program_info()["language_id"], "x86:LE:64:default")
        self.assertEqual(self.collector.list_imports()[0]["name"], "execve")

    def test_lists_functions_with_addresses(self) -> None:
        funcs = self.collector.list_functions()
        self.assertEqual([f["name"] for f in funcs], ["main", "execve"])
        self.assertEqual(funcs[0]["address"], "00101100")

    def test_decompile_by_address_then_name(self) -> None:
        self.assertIn("execve", self.collector.decompile_function("main", "00101100"))
        self.assertIn("execve", self.collector.decompile_function("main"))
        self.assertIsNone(self.collector.decompile_function("execve", "00101030"))

    def test_start_without_ghidra_dir_raises(self) -> None:
        collector = PyGhidraCollector(target_path=__file__, ghidra_install_dir="/nonexistent/ghidra")
        with self.assertRaises(RuntimeError):
            collector.start()


class _JavaIterator:
    """Mimics a Java Iterator for the collector's _iter_java helper."""

    def __init__(self, items):
        self._items = list(items)

    def hasNext(self):
        return bool(self._items)

    def next(self):
        return self._items.pop(0)


class _FakeData:

    def __init__(self, address, value, is_string=True):
        self._address = address
        self._value = value
        self._is_string = is_string

    def getAddress(self):
        return self._address

    def getValue(self):
        return self._value

    def hasStringValue(self):
        return self._is_string


class _FakeListing:

    def __init__(self, items):
        self._items = items

    def getDefinedData(self, forward):
        return _JavaIterator(self._items)


class _FakeProgram:

    def __init__(self, items):
        self._listing = _FakeListing(items)

    def getListing(self):
        return self._listing


def _fake_ghidra_modules(util_module):
    ghidra = types.ModuleType("ghidra")
    program = types.ModuleType("ghidra.program")
    ghidra.program = program
    program.util = util_module
    return {"ghidra": ghidra, "ghidra.program": program, "ghidra.program.util": util_module}


class TestStringExtraction(unittest.TestCase):

    def setUp(self) -> None:
        self.collector = PyGhidraCollector(target_path=__file__, max_strings=2)
        self.items = [
            _FakeData("00102000", "/bin/sh"),
            _FakeData("00102010", 42, is_string=False),
            _FakeData("00102020", "/tmp/output.dat"),
            _FakeData("00102030", "third string"),
        ]

    def test_uses_defined_string_iterator_when_available(self) -> None:
        util = types.ModuleType("ghidra.program.util")
        strings_only = [d for d in self.items if d.hasStringValue()]
        util.DefinedStringIterator = types.SimpleNamespace(forProgram=lambda program: _JavaIterator(strings_only))

        with patch.dict(sys.modules, _fake_ghidra_modules(util)):
            strings = self.collector._extract_strings(_FakeProgram([]), "sample")

        self.assertEqual([s["value"] for s in strings], ["/bin/sh", "/tmp/output.dat"])
        self.assertEqual(strings[0], {"address": "00102000", "value": "/bin/sh", "program": "sample"})

    def test_falls_back_to_listing_scan(self) -> None:
        util = types.ModuleType("ghidra.program.util")

        with patch.dict(sys.modules, _fake_ghidra_modules(util)):
            strings = self.collector._extract_strings(_FakeProgram(self.items), "sample")

        self.assertEqual([s["value"] for s in strings], ["/bin/sh", "/tmp/output.dat"])

    def test_failure_is_not_fatal(self) -> None:
        util = types.ModuleType("ghidra.program.util")

        def broken(program):
            raise RuntimeError("API changed")

        util.DefinedStringIterator = types.SimpleNamespace(forProgram=broken)

        with patch.dict(sys.modules, _fake_ghidra_modules(util)):
            with self.assertLogs("ghidra_syscall_analyzer.pyghidra_collector", level="WARNING"):
                strings = self.collector._extract_strings(_FakeProgram(self.items), "sample")

        self.assertEqual(strings, [])


class TestExtractClassFiles(unittest.TestCase):

    def test_extracts_classes_and_rejects_unsafe_members(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            jar = tmp_path / "app.jar"
            with zipfile.ZipFile(jar, "w") as zf:
                zf.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")
                zf.writestr("com/example/App.class", b"\xca\xfe\xba\xbe")
                zf.writestr("../evil.class", b"\xca\xfe\xba\xbe")
                zf.writestr("/abs.class", b"\xca\xfe\xba\xbe")

            out_dir = tmp_path / "out"
            extracted = extract_class_files(jar, out_dir)

            self.assertEqual([p.relative_to(out_dir.resolve()).as_posix() for p in extracted], ["com/example/App.class"])
            self.assertFalse((tmp_path / "evil.class").exists())

    def test_sample_applet_jar(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            extracted = extract_class_files(SAMPLES / "sample_applet.jar", Path(tmp))
            self.assertEqual([p.name for p in extracted], ["SampleApplet.class"])


@unittest.skipUnless(os.environ.get("GHIDRA_INSTALL_DIR"), "requires a Ghidra installation (GHIDRA_INSTALL_DIR)")
class TestPyGhidraLiveIntegration(unittest.TestCase):

    def test_collects_sample_elf(self) -> None:
        if not shutil.which("gcc"):
            self.skipTest("gcc not available to build the sample ELF")

        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp) / "sample_elf"
            subprocess.run(["gcc", "-O0", "-o", str(binary), str(SAMPLES / "sample_binary.c")], check=True)

            collector = PyGhidraCollector(target_path=binary)
            facts = collector.collect()

            # Mach-O symbols (macOS builds) carry a leading underscore, e.g. `_main`.
            def plain(name):
                return name.lstrip("_")

            names = {plain(f["name"]) for f in facts["functions"]}
            for expected in ("main", "file_io_operations", "network_operations", "process_execution"):
                self.assertIn(expected, names)

            main = next(f for f in facts["functions"] if plain(f["name"]) == "main")
            self.assertTrue(main["callsites"])
            self.assertIn("file_io_operations", {plain(c["to"]) for c in main["callsites"]})
            self.assertTrue(facts["program"]["language_id"])


if __name__ == "__main__":
    unittest.main()
