"""Tests for PyGhidraCollector: backend interface, archive handling, and live Ghidra integration."""

import os
import shutil
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path

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
