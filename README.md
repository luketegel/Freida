# 🛡️ Ghidra Syscall Analyzer (Headless MCP)

A robust Python-based security tool that takes in an **executable** (ELF, PE, Mach-O) or **Java Applet** (`.jar`, `.class`), decompiles it using **Ghidra MCP in Headless Mode** (strictly no GUI), analyzes all functions and imported symbols for **system calls**, and generates a structured, GitHub-flavored **Markdown report**.

---

## 🚀 Key Features

* **Ghidra MCP Headless Integration:** Communicates directly with Ghidra's headless decompiler via the Model Context Protocol (MCP JSON-RPC 2.0 over `stdio` or HTTP), running entirely in-process or via PyGhidra without ever launching the Ghidra GUI.
* **Multi-Format & Applet Support:**
  * **Linux:** ELF 32/64-bit binaries.
  * **Windows:** PE executables (Win32 / x64).
  * **macOS:** Mach-O 64-bit and Universal binaries.
  * **Java Applets:** JVM bytecode (`.class` files) and packaged Applets (`.jar` / `.war`).
* **Comprehensive Syscall Detection:**
  * **Direct Hardware Syscalls:** Detects raw inline assembly syscall instructions (`syscall`, `sysenter`, `int 0x80`, `svc #0`).
  * **Syscall Number Resolution:** Maps numeric `syscall(SYS_nr, ...)` calls to canonical system call names (e.g., `syscall(59)` → `execve`, `syscall(1)` → `write`).
  * **POSIX / Libc Wrappers:** Identifies standard system call wrappers across File I/O, Process/Thread Execution, Memory Management, Networking/Sockets, IPC/Signals, and Security/Privilege elevation.
  * **Windows NT Native Syscalls & Win32:** Detects `Nt*` / `Zw*` native system calls (`NtCreateFile`, `NtAllocateVirtualMemory`, `NtCreateThreadEx`) and Win32 wrappers (`CreateProcess`, `VirtualAllocEx`, `WriteProcessMemory`).
  * **macOS Mach Traps:** Recognizes Mach kernel messages and traps (`mach_msg_trap`, `vm_allocate`, `task_for_pid`).
  * **Java Applet / JVM System Invocations:** Detects sandbox escapes, host OS execution (`Runtime.getRuntime().exec`, `ProcessBuilder`), privilege escalation (`AccessController.doPrivileged`), direct disk I/O (`FileInputStream`, `FileOutputStream`), and socket connections (`Socket`, `ServerSocket`).
* **Rich Markdown Reporting:** Outputs an executive-ready Markdown report complete with target metadata, cryptographic hashes, visual category distribution bars, severity categorization, callsite inventory tables, and decompiled code evidence snippets.

---

## 📐 Architecture

```
                                  +-----------------------------+
                                  |   Executable / Applet File  |
                                  | (ELF, PE, Mach-O, JAR, Class|
                                  +--------------+--------------+
                                                 |
                                                 v
+-------------------------------------------------------------------------------+
|                       Ghidra Syscall Analyzer (Python)                        |
|                                                                               |
|  +--------------------+    MCP JSON-RPC      +-----------------------------+  |
|  |   GhidraMCPClient  | <------------------> |   Ghidra MCP Headless Svr   |  |
|  |  (stdio / HTTP)    |   (No GUI / PyGhidra)|   (Ghidra Decompiler Core)  |  |
|  +---------+----------+                      +-----------------------------+  |
|            |                                                                  |
|            | Extracts: Program Info, Imports, Decompiled C/Java Pseudocode    |
|            v                                                                  |
|  +--------------------+                                                       |
|  |  SyscallDetector   | ==> Direct Syscalls, Libc, Windows NT, Java JVM       |
|  +---------+----------+                                                       |
|            |                                                                  |
|            v                                                                  |
|  +--------------------+                                                       |
|  |  ReportGenerator   | ==> Formats Dashboard, Inventory & Code Evidence     |
|  +---------+----------+                                                       |
+------------|------------------------------------------------------------------+
             |
             v
   +--------------------+
   |   Markdown Report  |
   | (*_syscalls.md)    |
   +--------------------+
```

---

## 🛠️ Prerequisites & Installation

### Requirements
- Python 3.10 – 3.13 (or Python 3.11+)
- [Ghidra](https://ghidra-sre.org) 12.1.4+ (set via `GHIDRA_INSTALL_DIR`)
- [uv](https://docs.astral.sh/uv/) (optional, recommended for automatic headless GhidraMCP execution)

### Installation
Clone the repository and install dependencies:
```bash
git clone https://github.com/example/FreidaPrototype.git
cd FreidaPrototype
python3 -m pip install -e .
```

---

## 💻 Usage

### Basic Command
Analyze any binary or applet and output the results to a Markdown file:
```bash
python3 analyze_syscalls.py /path/to/target_binary -o report.md
```

### Running with Headless Ghidra MCP via `uvx`
To let `uvx` run the headless `ghidra-mcp` server in the background:
```bash
export GHIDRA_INSTALL_DIR=/path/to/ghidra_12.1.4_PUBLIC
python3 analyze_syscalls.py /path/to/target_binary \
    --mcp-cmd "uvx --python 3.13 --from 'ghidra-mcp[headless] @ git+https://github.com/LaurieWired/GhidraMCP' ghidra-mcp --headless --binary {binary}" \
    -o target_syscalls.md
```

### Connecting to an Existing Ghidra MCP Server
If you already have a headless Ghidra MCP server running on a host port:
```bash
python3 analyze_syscalls.py /path/to/target_binary \
    --server-url http://127.0.0.1:8081 \
    -o target_syscalls.md
```

### Dry-Run / Validation Mode (Testing without Ghidra)
To test the analysis pipeline, syscall detection rules, and report formatting without requiring a live Ghidra installation:
```bash
python3 analyze_syscalls.py ghidra_syscall_analyzer/samples/sample_binary \
    --mock-dry-run \
    -o sample_binary_syscalls.md
```

---

## 📋 Command-Line Options

| Flag | Description |
| :--- | :--- |
| `target` | Path to the executable or applet (ELF, PE, Mach-O, JAR, Class). |
| `-b, --binary` | Explicit flag to specify the target path. |
| `-o, --output` | Output Markdown report file path (default: `<target>_syscalls.md`). |
| `--mcp-cmd` | Custom command to spawn `ghidra-mcp` headless. |
| `--server-url` | URL of a running Ghidra MCP server (e.g. `http://127.0.0.1:8081`). |
| `--ghidra-dir` | Path to Ghidra root directory (overrides `GHIDRA_INSTALL_DIR`). |
| `--project-dir` | Optional directory to persist the Ghidra project across runs. |
| `--extension-jar`| Path to `GhidraMCP.jar` if not pre-installed in Ghidra. |
| `--timeout` | Timeout in seconds for backend decompilation queries (default: `120.0s`). |
| `--mock-dry-run` | Runs simulated decompilation to validate report generation. |
| `-v, --verbose` | Enables verbose debug logging. |

---

## 📊 Sample Markdown Report Output

Each report contains:
1. **Target Binary Metadata:** Cryptographic hashes (SHA-256, MD-5), file size, file format, and architecture.
2. **Analysis Dashboard:** Summary counters for decompiled functions, detected system calls, and severity levels.
3. **Category Breakdown:** Visual ASCII distribution bar chart showing distribution across File I/O, Process/Execution, Networking, Memory Management, and Security.
4. **Security & Behavioral Impact Observations:** High-level narrative flags for suspicious capabilities (e.g., shell spawns, RWX page modifications, remote socket connections).
5. **System Calls Inventory Table:** Every call site mapped with function name, address, line number, detection type, arguments, and severity.
6. **Decompiled Evidence & Callsite Context:** Syntax-highlighted code blocks with line annotations and expandable full decompiled function bodies.

---

## 🧪 Testing

Run the comprehensive unit test suite:
```bash
python3 -m unittest discover tests
```

---

## 📜 License
Apache-2.0 License.
