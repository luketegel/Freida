"""Tests for HeadlessOrchestrator backend selection and MCP command building."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ghidra_syscall_analyzer.orchestrator import DEFAULT_MCP_PACKAGE, HeadlessOrchestrator
from ghidra_syscall_analyzer.pyghidra_collector import PyGhidraCollector

SAMPLE_BINARY = Path(__file__).resolve().parent.parent / "ghidra_syscall_analyzer" / "samples" / "sample_binary"


class TestHeadlessOrchestrator(unittest.TestCase):

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.target = Path(self._tmp.name) / "my target.bin"
        self.target.write_bytes(b"\x7fELF\x02" + b"\x00" * 32)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_backend_defaults_to_pyghidra(self) -> None:
        orch = HeadlessOrchestrator(self.target)
        self.assertEqual(orch.backend, "pyghidra")

    def test_mcp_options_imply_mcp_backend(self) -> None:
        self.assertEqual(HeadlessOrchestrator(self.target, server_url="http://127.0.0.1:8081").backend, "mcp")
        self.assertEqual(HeadlessOrchestrator(self.target, custom_mcp_cmd="srv {binary}").backend, "mcp")

    def test_unknown_backend_rejected(self) -> None:
        with self.assertRaises(ValueError):
            HeadlessOrchestrator(self.target, backend="gui")

    def test_custom_mcp_cmd_respects_quotes_and_spaces_in_target(self) -> None:
        orch = HeadlessOrchestrator(
            self.target,
            custom_mcp_cmd="uvx --from 'ghidra-mcp[headless] @ git+https://example.com/repo' ghidra-mcp --binary {binary}",
        )
        cmd = orch.build_mcp_command()
        self.assertEqual(cmd[2], "ghidra-mcp[headless] @ git+https://example.com/repo")
        self.assertEqual(cmd[-1], str(self.target.resolve()))

    def test_default_cmd_prefers_uvx(self) -> None:
        paths = {"uvx": "/bin/uvx", "uv": "/bin/uv"}
        with patch("ghidra_syscall_analyzer.orchestrator.shutil.which", side_effect=paths.get):
            cmd = HeadlessOrchestrator(self.target).build_mcp_command()
        self.assertEqual(cmd[0], "/bin/uvx")
        self.assertIn(DEFAULT_MCP_PACKAGE, cmd)

    def test_default_cmd_uses_uv_tool_run_without_uvx(self) -> None:
        paths = {"uv": "/bin/uv"}
        with patch("ghidra_syscall_analyzer.orchestrator.shutil.which", side_effect=paths.get):
            cmd = HeadlessOrchestrator(self.target).build_mcp_command()
        self.assertEqual(cmd[:3], ["/bin/uv", "tool", "run"])

    def test_pyghidra_backend_without_ghidra_fails_clearly(self) -> None:
        with patch.dict("os.environ", {"GHIDRA_INSTALL_DIR": ""}):
            orch = HeadlessOrchestrator(self.target, backend="pyghidra")
            with self.assertRaises(RuntimeError) as ctx:
                orch.run_analysis()
        self.assertIn("GHIDRA_INSTALL_DIR", str(ctx.exception))


class TestRealGhidraOutputReplay(unittest.TestCase):
    """Replays PyGhidra facts captured from Ghidra 12.1.4 on samples/sample_binary (macOS arm64)."""

    def test_findings_have_callsite_addresses_and_no_import_duplicates(self) -> None:
        facts = json.loads((Path(__file__).parent / "fixtures" / "ghidra12_macos_arm64_sample_binary.json").read_text())
        collector = PyGhidraCollector(target_path=SAMPLE_BINARY)
        collector.load_facts(facts)

        orch = HeadlessOrchestrator(SAMPLE_BINARY)
        orch.collect_target_metadata()
        orch._analyze_via_client(collector)

        found = {(f.function_name, f.name): f for f in orch.findings}
        self.assertEqual(len(found), len(orch.findings))
        self.assertEqual(found[("_process_execution", "execve")].callsite_address, "100000660")
        self.assertEqual(found[("_memory_manipulation", "mprotect")].arguments, "uVar1,0x1000,7")
        self.assertIn(("_perform_direct_syscall", "direct_syscall"), found)
        self.assertEqual(
            {name for _, name in found},
            {"direct_syscall", "open", "write", "close", "socket", "connect",
             "fork", "execve", "exit", "mmap", "mprotect", "munmap"},
        )
        # Every imported API is also called, so no [IMPORT_TABLE] findings remain.
        self.assertNotIn("[IMPORT_TABLE]", {f.function_name for f in orch.findings})


if __name__ == "__main__":
    unittest.main()
