"""Model Context Protocol (MCP) Client for Ghidra MCP.

Implements lightweight, standard JSON-RPC 2.0 client over stdio and HTTP
transports to communicate with the Ghidra MCP server in headless mode.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import queue
import subprocess
import sys
import threading
import time
from typing import Any, Dict, List, Optional, Tuple, Union
import urllib.request
import urllib.error

from freida import __version__

logger = logging.getLogger("freida.mcp_client")


class MCPError(Exception):
    """Exception raised for MCP protocol errors."""
    pass


class GhidraMCPClient:
    """Communicates with Ghidra MCP server via stdio or HTTP."""

    def __init__(
        self,
        cmd: Optional[List[str]] = None,
        server_url: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
        timeout: float = 60.0,
    ) -> None:
        self.cmd = cmd
        self.server_url = server_url.rstrip("/") if server_url else None
        self.env = env or os.environ.copy()
        self.timeout = timeout

        self.process: Optional[subprocess.Popen[str]] = None
        self._stdout_queue: "queue.Queue[Optional[str]]" = queue.Queue()
        self._reader_thread: Optional[threading.Thread] = None
        self._msg_id = 0
        self._lock = threading.Lock()
        self.server_info: Dict[str, Any] = {}
        self.available_tools: Dict[str, Dict[str, Any]] = {}
        self._is_initialized = False

    def start(self) -> None:
        """Starts the process (if stdio) and performs the MCP handshake."""
        if self.cmd:
            logger.info("Spawning Ghidra MCP process: %s", " ".join(self.cmd))
            self.process = subprocess.Popen(
                self.cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,  # Line-buffered
                env=self.env,
            )
            # Start background thread to log stderr
            threading.Thread(target=self._log_stderr, daemon=True).start()
            self._ensure_stdout_reader()

        # Perform MCP handshake
        self._initialize()

    def _log_stderr(self) -> None:
        """Reads and logs stderr from the subprocess."""
        if not self.process or not self.process.stderr:
            return
        for line in self.process.stderr:
            clean = line.strip()
            if clean:
                logger.debug("[ghidra-mcp stderr] %s", clean)

    def _ensure_stdout_reader(self) -> None:
        """Starts a background thread that queues stdout lines so reads can time out."""
        if self._reader_thread is None and self.process and self.process.stdout:
            self._reader_thread = threading.Thread(target=self._read_stdout, daemon=True)
            self._reader_thread.start()

    def _read_stdout(self) -> None:
        """Pushes each stdout line onto the queue; None marks end of stream."""
        stdout = self.process.stdout if self.process else None
        try:
            while stdout is not None:
                line = stdout.readline()
                if not line:
                    break
                self._stdout_queue.put(line)
        except (OSError, ValueError):
            pass
        self._stdout_queue.put(None)

    def _next_id(self) -> int:
        with self._lock:
            self._msg_id += 1
            return self._msg_id

    def _send_stdio_request(self, method: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Sends a JSON-RPC request over stdio and waits for the response."""
        if not self.process or not self.process.stdin or not self.process.stdout:
            raise MCPError("Subprocess stdio is not connected")

        msg_id = self._next_id()
        payload = {
            "jsonrpc": "2.0",
            "id": msg_id,
            "method": method,
            "params": params or {},
        }
        msg_str = json.dumps(payload) + "\n"
        logger.debug("-> Sending MCP request: %s", msg_str.strip())

        try:
            self.process.stdin.write(msg_str)
            self.process.stdin.flush()
        except (BrokenPipeError, OSError) as e:
            raise MCPError(f"Failed to write to Ghidra MCP stdin: {e}") from e

        # Read lines until we get the JSON-RPC response matching msg_id
        self._ensure_stdout_reader()
        deadline = time.monotonic() + self.timeout
        while True:
            remaining = deadline - time.monotonic()
            try:
                if remaining <= 0:
                    raise queue.Empty
                line = self._stdout_queue.get(timeout=remaining)
            except queue.Empty:
                raise MCPError(
                    f"Timed out after {self.timeout:.0f}s waiting for Ghidra MCP response to '{method}'"
                ) from None

            if line is None:
                returncode = self.process.poll()
                raise MCPError(
                    f"Ghidra MCP process closed stdout unexpectedly (exit code: {returncode})"
                )

            line_str = line.strip()
            if not line_str:
                continue

            try:
                data = json.loads(line_str)
            except json.JSONDecodeError:
                logger.debug("Non-JSON stdout line: %s", line_str)
                continue

            if data.get("id") == msg_id:
                if "error" in data:
                    err = data["error"]
                    err_msg = err.get("message", str(err))
                    raise MCPError(f"Ghidra MCP error ({err.get('code')}): {err_msg}")
                return data.get("result", {})

    def _send_notification(self, method: str, params: Optional[Dict[str, Any]] = None) -> None:
        """Sends a notification (no response expected)."""
        if not self.process or not self.process.stdin:
            return
        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params or {},
        }
        msg_str = json.dumps(payload) + "\n"
        try:
            self.process.stdin.write(msg_str)
            self.process.stdin.flush()
        except OSError:
            pass

    def _send_http_request(self, method: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Sends request to Ghidra HTTP server endpoint."""
        if not self.server_url:
            raise MCPError("No server URL configured for HTTP request")

        msg_id = self._next_id()
        payload = {
            "jsonrpc": "2.0",
            "id": msg_id,
            "method": method,
            "params": params or {},
        }
        req_data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            f"{self.server_url}/mcp",
            data=req_data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                res_data = json.loads(resp.read().decode("utf-8"))
                if "error" in res_data:
                    raise MCPError(f"HTTP MCP error: {res_data['error']}")
                return res_data.get("result", {})
        except urllib.error.URLError as e:
            # Check if this is a direct REST server rather than JSON-RPC
            raise MCPError(f"Failed to communicate with Ghidra server at {self.server_url}: {e}") from e

    def send_request(self, method: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Dispatches request based on configured transport."""
        if self.process:
            return self._send_stdio_request(method, params)
        elif self.server_url:
            return self._send_http_request(method, params)
        else:
            raise MCPError("No transport available (neither cmd nor server_url specified)")

    def _initialize(self) -> None:
        """Executes the standard MCP initialization handshake."""
        init_params = {
            "protocolVersion": "2024-11-05",
            "capabilities": {
                "roots": {"listChanged": True},
                "sampling": {},
            },
            "clientInfo": {
                "name": "freida",
                "version": __version__,
            },
        }

        logger.info("Initializing MCP connection...")
        result = self.send_request("initialize", init_params)
        self.server_info = result.get("serverInfo", {})
        logger.info("Connected to MCP Server: %s", self.server_info)

        # Notify server of successful initialization
        self._send_notification("notifications/initialized")
        self._is_initialized = True

        # Refresh tool catalogue
        self.refresh_tools()

    def refresh_tools(self) -> Dict[str, Dict[str, Any]]:
        """Queries the server for available tools via tools/list."""
        resp = self.send_request("tools/list", {})
        raw_tools = resp.get("tools", [])
        self.available_tools = {}
        for tool in raw_tools:
            name = tool.get("name")
            if name:
                self.available_tools[name] = tool
        logger.info("Discovered %d MCP tools: %s", len(self.available_tools), list(self.available_tools.keys()))
        return self.available_tools

    def call_tool(self, name: str, arguments: Optional[Dict[str, Any]] = None) -> Any:
        """Invokes an MCP tool and unpacks the returned content."""
        params = {
            "name": name,
            "arguments": arguments or {},
        }
        res = self.send_request("tools/call", params)
        content_items = res.get("content", [])

        # Parse text content from MCP format
        output_parts: List[Any] = []
        for item in content_items:
            if item.get("type") == "text":
                text_content = item.get("text", "")
                # Attempt to parse embedded JSON if present
                try:
                    parsed_json = json.loads(text_content)
                    output_parts.append(parsed_json)
                except (json.JSONDecodeError, TypeError):
                    output_parts.append(text_content)
            else:
                output_parts.append(item)

        if len(output_parts) == 1:
            return output_parts[0]
        return output_parts

    def get_program_info(self) -> Dict[str, Any]:
        """Calls get_program_info to retrieve binary architecture and metadata."""
        if "get_program_info" in self.available_tools:
            res = self.call_tool("get_program_info")
            if isinstance(res, dict):
                return res
        return {}

    def list_functions(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Retrieves all functions from Ghidra using pagination."""
        all_funcs: List[Dict[str, Any]] = []
        offset = 0

        # Check which listing tool is registered
        tool_name = "list_functions" if "list_functions" in self.available_tools else "list_methods"

        while True:
            args: Dict[str, Any] = {"offset": offset, "limit": limit}
            try:
                res = self.call_tool(tool_name, args)
            except MCPError as e:
                logger.warning("Error fetching functions at offset %d: %s", offset, e)
                break

            items: List[Any] = []
            has_more = False

            if isinstance(res, dict):
                items = res.get("items", []) or res.get("functions", [])
                has_more = res.get("has_more", False)
            elif isinstance(res, list):
                items = res
                has_more = len(items) >= limit

            if not items:
                break

            for item in items:
                if isinstance(item, str):
                    all_funcs.append({"name": item, "address": None})
                elif isinstance(item, dict):
                    all_funcs.append(item)

            offset += len(items)
            if not has_more or len(items) < limit:
                break

        logger.info("Retrieved a total of %d functions from Ghidra", len(all_funcs))
        return all_funcs

    def list_imports(self) -> List[Dict[str, Any]]:
        """Lists imported symbols/libraries."""
        if "list_imports" in self.available_tools:
            try:
                res = self.call_tool("list_imports")
                if isinstance(res, list):
                    return res
                if isinstance(res, dict):
                    return res.get("items", []) or res.get("imports", [])
            except MCPError as e:
                logger.warning("Could not list imports: %s", e)
        return []

    def decompile_function(self, function_name: str, address: Optional[str] = None) -> Optional[str]:
        """Decompiles a function by address or name."""
        decompile_tool = None
        for candidate in ["decompile_function", "decompile", "get_decompilation"]:
            if candidate in self.available_tools:
                decompile_tool = candidate
                break

        if not decompile_tool:
            logger.warning("No decompilation tool found in MCP tools: %s", list(self.available_tools.keys()))
            return None

        # Build arguments based on tool schema
        schema = self.available_tools[decompile_tool].get("inputSchema", {}).get("properties", {})
        args: Dict[str, Any] = {}
        if "address" in schema and address:
            args["address"] = address
        elif "name" in schema:
            args["name"] = function_name
        elif "function_name" in schema:
            args["function_name"] = function_name
        else:
            # Default heuristic
            if address:
                args["address"] = address
            else:
                args["name"] = function_name

        try:
            res = self.call_tool(decompile_tool, args)
            if isinstance(res, str):
                return res
            if isinstance(res, dict):
                return res.get("decompiled_code") or res.get("c") or res.get("code") or str(res)
            return str(res)
        except MCPError as e:
            logger.debug("Decompilation failed for %s (%s): %s", function_name, address, e)
            return None

    def close(self) -> None:
        """Terminates subprocess and cleans up resources."""
        if self.process:
            logger.info("Closing Ghidra MCP subprocess...")
            try:
                self.process.terminate()
                self.process.wait(timeout=3.0)
            except Exception:
                try:
                    self.process.kill()
                except Exception:
                    pass
            self.process = None
