"""Tests for GhidraMCPClient protocol handling."""

import io
import json
import threading
import time
import unittest
from unittest.mock import MagicMock, patch

from ghidra_syscall_analyzer.mcp_client import GhidraMCPClient, MCPError


class TestGhidraMCPClient(unittest.TestCase):

    def test_stdio_jsonrpc_handshake_and_tool_call(self) -> None:
        client = GhidraMCPClient(cmd=["fake-mcp"])

        mock_proc = MagicMock()
        client.process = mock_proc

        # Prepare simulated stdout lines for:
        # 1. initialize response
        # 2. tools/list response
        # 3. get_program_info response
        # 4. list_functions response
        # 5. decompile_function response
        responses = [
            json.dumps({"jsonrpc": "2.0", "id": 1, "result": {"serverInfo": {"name": "ghidra-mcp", "version": "2.0"}}}),
            json.dumps({"jsonrpc": "2.0", "id": 2, "result": {"tools": [
                {"name": "get_program_info", "description": "Program info"},
                {"name": "list_functions", "description": "List functions"},
                {"name": "decompile_function", "description": "Decompile function", "inputSchema": {"properties": {"address": {}, "name": {}}}},
            ]}}),
            json.dumps({"jsonrpc": "2.0", "id": 3, "result": {"content": [{"type": "text", "text": json.dumps({"name": "test_bin", "language_id": "x86:64"})}]}}),
            json.dumps({"jsonrpc": "2.0", "id": 4, "result": {"content": [{"type": "text", "text": json.dumps({"items": [{"name": "main", "address": "0x401000"}], "has_more": False})}]}}),
            json.dumps({"jsonrpc": "2.0", "id": 5, "result": {"content": [{"type": "text", "text": "int main() { open(\"/tmp/foo\", 0); return 0; }"}]}}),
        ]

        def readline_side_effect():
            if responses:
                return responses.pop(0) + "\n"
            return ""

        mock_proc.stdout.readline.side_effect = readline_side_effect
        mock_proc.stdin = MagicMock()

        # Test initialize
        client._initialize()
        self.assertEqual(client.server_info.get("name"), "ghidra-mcp")
        self.assertIn("list_functions", client.available_tools)
        self.assertIn("decompile_function", client.available_tools)

        # Test get_program_info
        prog_info = client.get_program_info()
        self.assertEqual(prog_info.get("name"), "test_bin")
        self.assertEqual(prog_info.get("language_id"), "x86:64")

        # Test list_functions
        funcs = client.list_functions()
        self.assertEqual(len(funcs), 1)
        self.assertEqual(funcs[0]["name"], "main")

        # Test decompile_function
        code = client.decompile_function("main", "0x401000")
        self.assertIn("open", code)

    def test_mcp_error_propagation(self) -> None:
        client = GhidraMCPClient(cmd=["fake-mcp"])
        mock_proc = MagicMock()
        client.process = mock_proc

        error_response = json.dumps({
            "jsonrpc": "2.0",
            "id": 1,
            "error": {"code": -32601, "message": "Method not found"},
        })
        mock_proc.stdout.readline.side_effect = [error_response + "\n", ""]
        mock_proc.stdin = MagicMock()

        with self.assertRaises(MCPError) as ctx:
            client.send_request("non_existent_method")
        self.assertIn("Method not found", str(ctx.exception))

    def test_stdio_request_times_out_when_server_is_silent(self) -> None:
        client = GhidraMCPClient(cmd=["fake-mcp"], timeout=0.2)
        mock_proc = MagicMock()
        client.process = mock_proc

        never_answers = threading.Event()

        def blocking_readline():
            never_answers.wait(5)
            return ""

        mock_proc.stdout.readline.side_effect = blocking_readline
        mock_proc.stdin = MagicMock()

        start = time.monotonic()
        with self.assertRaises(MCPError) as ctx:
            client.send_request("tools/list")
        never_answers.set()

        self.assertIn("Timed out", str(ctx.exception))
        self.assertLess(time.monotonic() - start, 2.0)

    def test_stdio_reports_closed_stdout(self) -> None:
        client = GhidraMCPClient(cmd=["fake-mcp"])
        mock_proc = MagicMock()
        client.process = mock_proc
        mock_proc.stdout.readline.side_effect = ["not json\n", ""]
        mock_proc.poll.return_value = 1
        mock_proc.stdin = MagicMock()

        with self.assertRaises(MCPError) as ctx:
            client.send_request("tools/list")
        self.assertIn("closed stdout", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
