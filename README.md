# 🛡️ Ghidra Syscall Analyzer (Headless MCP)

A robust Python-based security tool that takes in an **executable** (ELF, PE, Mach-O) or **Java Applet** (`.jar`, `.class`), decompiles it with **headless Ghidra** (strictly no GUI), analyzes all functions and imported symbols for **system calls**, and generates a structured, GitHub-flavored **Markdown report** plus a **model context bundle** (JSON) for AI-driven analysis.

Initial context is collected in-process with **PyGhidra**. A **Ghidra MCP** server is the exploration path: the context bundle tells a model how to launch it so it can query the binary in more detail.

---

## 🚀 Key Features

* **PyGhidra Headless Collection (default):** Loads the target in-process with PyGhidra, runs Ghidra auto-analysis, and extracts program metadata, imports/exports, every function with its callsites, decompiled C, and defined strings, without ever launching the Ghidra GUI.
* **Model Context Bundle:** Writes `<target>_context.json`, a compact, address-annotated summary sized for a model's context window, with a `truncated` section listing what was left out and an `exploration` section describing the Ghidra MCP server.
* **Ghidra MCP Backend (optional):** Can instead drive a Ghidra MCP server (JSON-RPC 2.0 over `stdio` or HTTP) with `--backend mcp`, `--mcp-cmd`, or `--server-url`.
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
|  +--------------------+    in-process        +-----------------------------+  |
|  | PyGhidraCollector  | <------------------> |  Ghidra (headless, no GUI)  |  |
|  |     (default)      |      (PyGhidra)      |  Analysis + Decompiler      |  |
|  +---------+----------+                      +-----------------------------+  |
|  | GhidraMCPClient    |   MCP JSON-RPC (optional backend / model exploration) |
|  +---------+----------+                                                       |
|            |                                                                  |
|            | Extracts: Program Info, Imports, Functions + Callsites,          |
|            |           Decompiled Pseudocode, Strings                         |
|            v                                                                  |
|  +--------------------+                                                       |
|  |  SyscallDetector   | ==> Direct Syscalls, Libc, Windows NT, Java JVM       |
|  +---------+----------+                                                       |
|            |                                                                  |
|            v                                                                  |
|  +--------------------+                                                       |
|  |  ReportGenerator   | ==> Formats Dashboard, Inventory & Code Evidence     |
|  |  ContextBuilder    | ==> Model-ready JSON bundle                          |
|  +---------+----------+                                                       |
+------------|------------------------------------------------------------------+
             |
             v
   +--------------------+   +----------------------+
   |   Markdown Report  |   | Model Context Bundle |
   | (*_syscalls.md)    |   | (*_context.json)     |
   +--------------------+   +----------------------+
```

---

## 🛠️ Prerequisites & Installation

### Requirements
- Python 3.10 – 3.13 (or Python 3.11+)
- [Ghidra](https://ghidra-sre.org) 12.1.4+ (set via `GHIDRA_INSTALL_DIR`)
- A JDK supported by your Ghidra release (Ghidra 12.x requires JDK 21)
- [PyGhidra](https://pypi.org/project/pyghidra/) for the default backend (installed by the `ghidra` extra, or from the wheel Ghidra bundles under `Ghidra/Features/PyGhidra/pypkg/dist`)
- [uv](https://docs.astral.sh/uv/) (optional, for launching a Ghidra MCP server with `uvx`)

### Installation
Clone the repository and install dependencies:
```bash
git clone https://github.com/luketegel/Freida.git
cd Freida
python3 -m pip install -e '.[ghidra]'
```

---

## 💻 Usage

### Basic Command (PyGhidra backend)
Analyze any binary or applet, writing the Markdown report and the model context bundle:
```bash
export GHIDRA_INSTALL_DIR=/path/to/ghidra_12.1.4_PUBLIC
python3 analyze_syscalls.py /path/to/target_binary -o report.md --context-out context.json
```
JAR/WAR archives are unpacked and each `.class` file is analyzed as its own Ghidra program.

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
| `--context-out` | Output model context JSON path (default: `<target>_context.json`). |
| `--backend` | `pyghidra` (default) or `mcp` (implied by `--mcp-cmd` / `--server-url`). |
| `--mcp-cmd` | Custom command to spawn a headless Ghidra MCP server (`{binary}` is replaced with the target path). |
| `--server-url` | URL of a running Ghidra MCP server (e.g. `http://127.0.0.1:8081`). |
| `--ghidra-dir` | Path to Ghidra root directory (overrides `GHIDRA_INSTALL_DIR`). |
| `--project-dir` | Optional directory to persist the Ghidra project across runs. |
| `--extension-jar`| Path to `GhidraMCP.jar` if not pre-installed in Ghidra. |
| `--timeout` | Timeout in seconds for each MCP request (default: `120.0s`). |
| `--max-functions` | Maximum functions to collect with the PyGhidra backend (default: all). |
| `--decompile-timeout` | Per-function decompilation timeout for the PyGhidra backend (default: `60`). |
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

## 🤖 Model Context Bundle

`<target>_context.json` is the starting context for an AI model analyzing the binary:

| Key | Contents |
| :--- | :--- |
| `target` | File name, size, SHA-256/MD5, detected file type, Ghidra architecture, backend. |
| `program` | Ghidra language/compiler IDs, image base, format, entry points (and per-class members for JARs). |
| `imports` / `exports` | External symbols with library and address; external entry points. |
| `syscall_summary` / `syscall_findings` | Detected system calls by severity and category, with function, line, and arguments. |
| `functions` | Every collected function: address, size, callees, callsites (`to`, `at`), detected syscalls; decompiled C for entry points and functions with findings. |
| `strings` | Defined strings with addresses (capped). |
| `truncated` | What was capped or omitted, so the model knows to explore further. |
| `exploration` | How to reach a Ghidra MCP server (launch command or URL, and its tools when known). |

---

## 🧪 Testing

Run the comprehensive unit test suite:
```bash
python3 -m unittest discover tests
```
The live Ghidra integration test runs only when `GHIDRA_INSTALL_DIR` is set (it compiles `samples/sample_binary.c` with `gcc`).

---

## 📜 License
Apache-2.0 License.
