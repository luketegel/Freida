# 🛡️ Ghidra Syscall Analyzer (Headless MCP)

A robust Python-based security tool that takes in a **native executable** (ELF, PE, Mach-O), decompiles it with **headless Ghidra** (strictly no GUI), analyzes all functions and imported symbols for **system calls**, and generates a structured, GitHub-flavored **Markdown report** plus a **model context bundle** (JSON) for AI-driven analysis.

Initial context is collected in-process with **PyGhidra**. A **Ghidra MCP** server is the exploration path: the context bundle tells a model how to launch it so it can query the binary in more detail.

---

## 🚀 Key Features

* **PyGhidra Headless Collection (default):** Loads the target in-process with PyGhidra, runs Ghidra auto-analysis, and extracts program metadata, imports/exports, every function with its callsites, decompiled C, and defined strings, without ever launching the Ghidra GUI.
* **Model Context and Facts:** Writes `<target>_context.json`, a compact, address-annotated summary sized for a model's context window, and `<target>_facts.json` with everything uncapped: strings and global data with cross-references, data types, memory map with entropy, hardening, indicators, function signatures and callers.
* **Ghidra MCP Backend (optional):** Can instead drive a Ghidra MCP server (JSON-RPC 2.0 over `stdio` or HTTP) with `--backend mcp`, `--mcp-cmd`, or `--server-url`.
* **Multi-Format Support:**
  * **Linux:** ELF 32/64-bit binaries.
  * **Windows:** PE executables (Win32 / x64).
  * **macOS:** Mach-O 64-bit and Universal binaries.
  * Java `.class` / `.jar` files are not supported and are rejected with an error.
* **Comprehensive Syscall Detection:**
  * **Direct Hardware Syscalls:** Detects raw syscall instructions (`syscall`, `sysenter`, `int 0x80`, `svc #0`), including Ghidra's decompiled forms such as `CallSupervisor(0)`.
  * **Exact Call Sites:** With the PyGhidra backend, each API call is tied to the address of the call instruction from Ghidra's own call references.
  * **Syscall Number Resolution:** Maps numeric `syscall(SYS_nr, ...)` calls to canonical system call names (e.g., `syscall(59)` → `execve`, `syscall(1)` → `write`).
  * **POSIX / Libc Wrappers:** Identifies standard system call wrappers across File I/O, Process/Thread Execution, Memory Management, Networking/Sockets, IPC/Signals, and Security/Privilege elevation.
  * **Windows NT Native Syscalls & Win32:** Detects `Nt*` / `Zw*` native system calls (`NtCreateFile`, `NtAllocateVirtualMemory`, `NtCreateThreadEx`) and Win32 wrappers (`CreateProcess`, `VirtualAllocEx`, `WriteProcessMemory`).
  * **macOS Mach Traps:** Recognizes Mach kernel messages and traps (`mach_msg_trap`, `vm_allocate`, `task_for_pid`); Mach-O's leading underscores (`_open`) are handled.
* **Rich Markdown Reporting:** Outputs an executive-ready Markdown report complete with target metadata, cryptographic hashes, visual category distribution bars, severity categorization, callsite inventory tables, and decompiled code evidence snippets.

---

## 📐 Architecture

```
                                  +-----------------------------+
                                  |      Native Executable      |
                                  |      (ELF, PE, Mach-O)      |
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
|  |  SyscallDetector   | ==> Direct Syscalls, Libc, Windows NT, Mach Traps     |
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

### macOS Setup (Apple Silicon)
- **Do not use Apple's built-in Python** (`/usr/bin/python3`). Its code signing blocks the JVM's JIT compiler, and `pyghidra.start()` crashes with `SIGBUS` in `CodeHeap::allocate`. Use a uv-managed or Homebrew Python instead:
  ```bash
  uv venv --python 3.12 --python-preference only-managed .venv
  source .venv/bin/activate
  ```
- **Homebrew Ghidra** (`brew install ghidra`) lives under `libexec`, and needs JDK 21 even if another Java is your default:
  ```bash
  export GHIDRA_INSTALL_DIR="$(brew --prefix ghidra)/libexec"
  export JAVA_HOME="$(brew --prefix openjdk@21)/libexec/openjdk.jdk/Contents/Home"
  uv pip install "$GHIDRA_INSTALL_DIR"/Ghidra/Features/PyGhidra/pypkg/dist/pyghidra-*.whl
  uv pip install -e .
  python -c "import pyghidra; pyghidra.start(); print('ok')"
  ```

---

## 💻 Usage

### Basic Command (PyGhidra backend)
Analyze a binary, writing the Markdown report and the model context bundle:
```bash
export GHIDRA_INSTALL_DIR=/path/to/ghidra_12.1.4_PUBLIC
python3 analyze_syscalls.py /path/to/target_binary -o report.md --context-out context.json --facts-out facts.json
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
| `target` | Path to the executable (ELF, PE, Mach-O). |
| `-b, --binary` | Explicit flag to specify the target path. |
| `-o, --output` | Output Markdown report file path (default: `<target>_syscalls.md`). |
| `--context-out` | Output model context JSON path (default: `<target>_context.json`). |
| `--facts-out` | Output full, uncapped facts JSON path (default: `<target>_facts.json`). |
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

## 🤖 Model Context and Facts

Each real run writes two JSON files for an AI model analyzing the binary:

* **`<target>_context.json`**: the starting context, sized for a model's context window. Sections are relevance-ranked and capped, and file-format metadata that no code uses (load commands, symbol and string tables, loader structures) is left out; `truncated` lists exactly what was cut and names the facts file.
* **`<target>_facts.json`**: everything collected, uncapped, including full decompiled code for every function and up to 50 cross-references per string or global. Strings, globals, data types and indicators carry `origin`: `program` or `file_format`.

| Key | Contents |
| :--- | :--- |
| `target` | File name, size, SHA-256/MD5, detected file type, Ghidra architecture, backend. |
| `program` / `program_metadata` | Ghidra language/compiler IDs, image base, format, entry points; Ghidra's *Program Information* fields (compiler, format details, required libraries). |
| `hardening` | PIE, NX, RELRO (from the file header), stack canary, FORTIFY, RWX sections, and whether the binary looks stripped. Unknown values are `null`. |
| `memory_map` | Sections/segments with start, end, size, `rwx` permissions, and byte entropy (high entropy suggests packed or encrypted data). |
| `imports` / `exports` | External symbols with library and address; external entry points. |
| `syscall_summary` / `syscall_findings` | Detected system calls by severity and category, with function, exact call address, line, and arguments. |
| `functions` | Every collected function: address, size, signature, calling convention, callers, callees, callsites (`to`, `at`), detected syscalls; decompiled C (context: entry points and functions with findings; facts: all). |
| `strings` | All defined strings with section, encoding, and the functions that use them (following pointers such as `PTR_s__bin_ls`). Context: referenced strings first. |
| `globals` | Global data (variables, pointers, tables) with label, type, size, section, value preview, pointer target, and referencing functions. |
| `data_types` | Structs, unions, enums and typedefs the program uses (in globals, signatures, locals and decompiler-inferred variables) with fields, offsets and sizes. |
| `indicators` | URLs, IPs, domains, emails, file paths, registry keys and shell commands found in strings, with the functions that use them. |
| `truncated` | (context only) What was capped or omitted and `full_facts_file`. |
| `exploration` | How to reach a Ghidra MCP server (launch command or URL, and its tools when known). |

---

## 🧠 AI Report: Behavioral Overview (Gemini)

`freida-report` turns the context and facts files into an analysis report using the Gemini API (Google AI Studio). The model reads the context, may call up to **3 read-only lookup tools** over the facts file (`get_function`, `get_references`, `search_strings`, `get_data_type`), and writes a structured **Behavioral Overview**: summary, execution flow, behaviors with cited evidence, assessment, and limitations. Every cited function and address is checked against the facts and flagged if it can't be found.

```bash
export GEMINI_API_KEY=...            # create one at https://aistudio.google.com/apikey
python analyze_syscalls.py ghidra_syscall_analyzer/samples/sample_binary --context-out sample_binary_context.json --facts-out sample_binary_facts.json
freida-report sample_binary_context.json --dry-run    # estimate only, no generation
freida-report sample_binary_context.json              # writes sample_binary_overview.md / .json
```

Each run prints an **estimated cost** before generating (exact input size via Gemini's free `countTokens`) and the **actual cost** afterwards (from the API's usage data); both are recorded in `<target>_overview.json` and the report footer. `--max-cost` (default $1.00) refuses runs whose worst-case estimate is higher and stops tool use if the spend approaches it.

**Estimated cost per run, default model `gemini-3.6-flash`** ($1.50 / 1M input, $7.50 / 1M output incl. thinking; list prices, Oct 2026):

| Binary | Context | No tool calls | 3 tool calls (worst case) |
| :--- | :--- | :--- | :--- |
| `ghidra_syscall_analyzer/samples/sample_binary` | ~8.5k tokens | ~$0.035 | ~$0.12 |
| Typical program (100–500 functions) | ~50k tokens | ~$0.10 | ~$0.38 |
| Large program (context at its caps) | ~120k tokens | ~$0.20 | ~$0.80 |

Google currently lists a $0.75 / 1M input promotion for gemini-3.6-flash through 2026-12-31, and implicit caching bills repeated context at ~10% of the input price; both only lower the actual cost. Cheaper models: `--model gemini-3.5-flash-lite` (~$0.01–0.17 per run, about a fifth of the cost) or `gemini-3.1-flash-lite`. Prices are built in per model and can be overridden with `--price-in`, `--price-cached`, `--price-out`.

| Option | Description |
| :--- | :--- |
| `--facts` | Facts JSON for the lookup tools (default: sibling `<target>_facts.json`; without it the model gets no tools). |
| `--model` | Gemini model (default `gemini-3.6-flash`). |
| `--max-tool-calls` | Lookup tool budget per run (default `3`). |
| `--thinking` | `minimal`, `low` (default), `medium`, `high`; higher levels cost more output tokens. |
| `--max-cost` | Worst-case spend limit in USD (default `1.00`). |
| `--dry-run` | Print the estimate only (works without an API key, approximating tokens from size). |

> **Data use:** on the free tier, Google may use prompts and responses to improve its products; with billing enabled (paid tier) it does not. Use a billing-enabled key for proprietary or sensitive binaries. Local file paths are stripped from the prompt.

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
