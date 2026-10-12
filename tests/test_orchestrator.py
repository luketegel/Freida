"""Tests for HeadlessOrchestrator backend selection and MCP command building."""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ghidra_syscall_analyzer.orchestrator import DEFAULT_MCP_PACKAGE, HeadlessOrchestrator


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


if __name__ == "__main__":
    unittest.main()
