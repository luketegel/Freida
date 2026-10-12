# 🛡️ Ghidra Syscall Analyzer (Headless MCP)

A robust Python-based security tool that takes in a **native executable** (ELF, PE, Mach-O), decompiles it with **headless Ghidra** (strictly no GUI), analyzes all functions and imported symbols for **system calls**, and generates a structured, GitHub-flavored **Markdown report** and a matching **PDF report**, plus a **model context bundle** (JSON) for AI-driven analysis.

Initial context is collected in-process with **PyGhidra**. A **Ghidra MCP** server is the exploration path: the context bundle tells a model how to launch it so it can query the binary in more detail.

---

## 🚀 Key Features

* **PyGhidra Headless Collection (default):** Loads the target in-process with PyGhidra, runs Ghidra auto-analysis, and extracts program metadata, imports/exports, every function with its callsites, decompiled C, and defined strings, without ever launching the Ghidra GUI.
* **Model Context and Facts:** Writes `binary_context.json`, a compact, address-annotated summary sized for a model's context window, and `binary_facts.json` with everything uncapped: strings and global data with cross-references, data types, memory map with entropy, hardening, indicators, function signatures and callers.
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
* **Clean PDF Reports:** Every Markdown report (the syscall report and the AI Behavioral Overview) is also written as a printable PDF with severity colors, distribution bars, paginated tables and code listings, ready to share with people who don't read Markdown.

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
|  |  PdfReportGenerator| ==> Same report as a printable PDF                   |
|  |  ContextBuilder    | ==> Model-ready JSON bundle                          |
|  +---------+----------+                                                       |
+------------|------------------------------------------------------------------+
             |
             v
   +--------------------+   +----------------------+
   | Markdown + PDF     |   | Model Context Bundle |
   | (*_syscalls.md/pdf)|   | (binary_context.json)|
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
Analyze a binary, writing the Markdown and PDF reports and the model context bundle:
```bash
export GHIDRA_INSTALL_DIR=/path/to/ghidra_12.1.4_PUBLIC
python3 analyze_syscalls.py /path/to/target_binary -o report.md --context-out context.json --facts-out facts.json
```
This writes `report.md` and `report.pdf` (the PDF goes next to the Markdown file with a `.pdf` suffix; change it with `--pdf-out`, or skip it with `--no-pdf`).

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
| `--pdf-out` | Output PDF report path (default: the Markdown path with a `.pdf` suffix, e.g. `<target>_syscalls.pdf`). |
| `--no-pdf` | Do not write the PDF report. |
| `--context-out` | Output model context JSON path (default: `binary_context.json`). |
| `--facts-out` | Output full, uncapped facts JSON path (default: `binary_facts.json`). |
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

The PDF report (`*_syscalls.pdf`) opens with a **TL;DR** verdict: *Malicious*, *Suspicious*, *Needs Review*, *Likely Benign* or *Unknown*, with a confidence and one sentence of why. The verdict is rule-based on the detected system calls (e.g. writing into another process and starting a thread there is *Malicious*; network access plus starting programs is *Suspicious*), not a malware scan; the AI overview below gives a model's judgement. The report then has the same sections, laid out for print: colored severity labels, drawn distribution bars, an inventory table that repeats its header across pages, and code listings (the first 40 lines of each function, long lines wrapped).

## 🤖 Model Context and Facts

Each real run writes two JSON files for an AI model analyzing the binary:

* **`binary_context.json`**: the starting context, sized for a model's context window. Sections are relevance-ranked and capped, and file-format metadata that no code uses (load commands, symbol and string tables, loader structures) is left out; `truncated` lists exactly what was cut and names the facts file.
* **`binary_facts.json`**: everything collected, uncapped, including full decompiled code for every function and up to 50 cross-references per string or global. Strings, globals, data types and indicators carry `origin`: `program` or `file_format`.

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

The lookup tools read `binary_facts.json` locally; no Ghidra or MCP server runs during a report.

> **zsh tip:** the commands below have no inline `# comments` because zsh treats them as arguments by default. To paste commented snippets safely, run `setopt interactivecomments` (or add it to `~/.zshrc`).

### 1. Install or update

The `freida-report` command is registered when the package is installed. Re-run this after pulling changes that add commands:

```bash
source .venv/bin/activate
uv pip install -e .
rehash
```

(`python3 -m pip install -e .` works too.) Without installing, the same tool runs as `python -m ghidra_syscall_analyzer.report_agent`.

### 2. Gemini API key

1. Create a key at <https://aistudio.google.com/apikey> (**Create API key**, then pick or create a Google Cloud project).
2. Decide on the tier. New keys start on the **free tier**: no cost within rate limits, but Google may use prompts and responses to improve its products. **Enable billing** for the project (AI Studio offers *Set up billing*) before analyzing proprietary or sensitive binaries; on the paid tier your data is not used for that.
3. Make the key available. For the current terminal only:

   ```bash
   export GEMINI_API_KEY="AIza...your key..."
   ```

   To keep it across terminals without storing it in plain text, put it in the macOS Keychain (the first command prompts for the key) and load it from `~/.zshrc`:

   ```bash
   security add-generic-password -a "$USER" -s GEMINI_API_KEY -w
   echo 'export GEMINI_API_KEY="$(security find-generic-password -a "$USER" -s GEMINI_API_KEY -w)"' >> ~/.zshrc
   source ~/.zshrc
   ```

4. Check that it works (free; prints the model's details, or an `API_KEY_INVALID` / `PERMISSION_DENIED` error):

   ```bash
   curl -s "https://generativelanguage.googleapis.com/v1beta/models/gemini-3.6-flash" -H "x-goog-api-key: $GEMINI_API_KEY" | head -5
   ```

If a key is ever exposed, delete it in AI Studio and create a new one.

### 3. Generate a report

```bash
python analyze_syscalls.py /path/to/any_binary
freida-report --dry-run
freida-report
```

1. `analyze_syscalls.py` runs Ghidra and writes `binary_context.json` and `binary_facts.json` in the current folder, whatever the binary is called.
2. `freida-report --dry-run` prints the estimated cost and stops (optional; it costs nothing). The estimate says *counted by Gemini* when the key works.
3. `freida-report` prints the estimate again, generates the report, writes `binary_overview.md` (the report), `binary_overview.pdf` (the same report as a PDF, opening with a TL;DR of the model's verdict and its reason) and `binary_overview.json` (structured result, per-request usage and cost, tool-call trace), and prints the **actual cost**.

Each analysis overwrites the `binary_*` files. To keep several, name them: `python analyze_syscalls.py /path/to/mybin --context-out mybin_context.json --facts-out mybin_facts.json`, then `freida-report mybin_context.json`, which picks up `mybin_facts.json` and writes `mybin_overview.md` and `mybin_overview.pdf`.

A successful run looks like:

```text
[i] Model gemini-3.6-flash, up to 3 tool call(s).
[i] Input: 8,428 tokens (counted by Gemini). Estimated cost: $0.0351 (no tool calls) to $0.1244 (3 tool calls) at $1.50 in / $7.50 out per 1M tokens.
[+] Behavioral overview written to:
    /path/to/binary_overview.md
    /path/to/binary_overview.json
    /path/to/binary_overview.pdf
[+] Actual cost: $0.0... (N request(s), N tool call(s), ... tokens incl. ... thinking)
```

### 4. Cost

Each run prints an **estimated cost** before generating (exact input size via Gemini's free `countTokens`) and the **actual cost** afterwards (from the API's usage data); both are recorded in `binary_overview.json` and the report footer.

**Estimated cost per run, default model `gemini-3.6-flash`** ($1.50 / 1M input, $7.50 / 1M output incl. thinking; list prices, Oct 2026):

| Binary | Context | No tool calls | 3 tool calls (worst case) |
| :--- | :--- | :--- | :--- |
| `ghidra_syscall_analyzer/samples/sample_binary` | ~8.5k tokens | ~$0.035 | ~$0.12 |
| Typical program (100–500 functions) | ~50k tokens | ~$0.10 | ~$0.38 |
| Large program (context at its caps) | ~120k tokens | ~$0.20 | ~$0.80 |

Every tool call makes the model send the whole context again, so cost grows with context size × tool calls. Google currently lists a $0.75 / 1M input promotion for gemini-3.6-flash through 2026-12-31, and implicit caching bills repeated context at ~10% of the input price; both only lower the actual cost, but caching is not guaranteed, so estimates ignore it. Cheaper models: `--model gemini-3.5-flash-lite` (about a fifth of the cost) or `gemini-3.1-flash-lite`. Prices are built in per model and can be overridden with `--price-in`, `--price-cached`, `--price-out`.

#### When the cost guard stops a run

`--max-cost` (default $1.00) refuses a run whose worst-case estimate is higher, before anything is spent, and stops tool use mid-run if the spend approaches it:

```text
[i] Input: 167,793 tokens (counted by Gemini). Estimated cost: $0.2742 (no tool calls) to $1.0806 (3 tool calls) ...
[!] Worst-case estimate $1.0806 exceeds --max-cost $1.00. Raise --max-cost or lower --max-tool-calls.
```

Pick one:

| Command | Effect |
| :--- | :--- |
| `freida-report --max-tool-calls 0` | One request, no lookups: cheapest (the "no tool calls" estimate). |
| `freida-report --max-tool-calls 1` | One lookup; roughly half the worst case. |
| `freida-report --max-cost 1.25` | Keep all 3 lookups and accept the higher ceiling (actual cost is usually lower). |
| `freida-report --model gemini-3.5-flash-lite` | Same run on a model about five times cheaper. |

### 5. See which lookups the model made

The report footer and the final `Actual cost` line show the counts (e.g. `2 request(s), 1 tool call(s)`). For the details:

```bash
python - <<'EOF'
import json
d = json.load(open("binary_overview.json"))
print("requests:", d["usage"]["total"]["requests"], "| tool calls:", d["usage"]["total"]["tool_calls"])
for c in d["tool_calls"]:
    note = " (refused: over budget)" if c["skipped"] else ""
    print(f'- {c["name"]}({c["args"]}) -> {c["result_bytes"]} bytes{note}')
EOF
```

An empty list means the model answered from the context alone. If it regularly uses the whole budget and the report's *Limitations* mention functions it couldn't inspect, raise `--max-tool-calls`.

### 6. Options

| Option | Description |
| :--- | :--- |
| `context` | Context JSON to report on (default: `binary_context.json`). Pass another path to report on a saved analysis. |
| `--facts` | Facts JSON for the lookup tools (default: the matching `*_facts.json`, e.g. `binary_facts.json`; without it the model gets no tools). |
| `-o, --output` / `--json-out` | Report Markdown / JSON paths (default: `binary_overview.md` / `binary_overview.json`). |
| `--pdf-out` / `--no-pdf` | PDF report path (default: `binary_overview.pdf`) / skip the PDF. |
| `--model` | Gemini model (default `gemini-3.6-flash`). |
| `--max-tool-calls` | Lookup tool budget per run (default `3`). |
| `--thinking` | `minimal`, `low` (default), `medium`, `high`; higher levels cost more output tokens. |
| `--max-cost` | Worst-case spend limit in USD (default `1.00`). |
| `--price-in` / `--price-cached` / `--price-out` | Override model prices (USD per 1M tokens). |
| `--dry-run` | Print the estimate only (works without an API key, approximating tokens from size). |
| `-v, --verbose` | Debug logging. |

### Troubleshooting

| Message | Fix |
| :--- | :--- |
| `zsh: command not found: freida-report` | Install the package (step 1), or use `python -m ghidra_syscall_analyzer.report_agent`. |
| `No Gemini API key found` | Set `GEMINI_API_KEY` in this terminal (step 2). |
| `binary_context.json not found` | Run `python analyze_syscalls.py /path/to/binary` first, in the same folder. |
| `Worst-case estimate … exceeds --max-cost` | See *When the cost guard stops a run* above. |
| `Gemini API error 401/403` | Key invalid or disabled; check it in AI Studio. |
| `Gemini API error 400: …` | The request was rejected; run with `-v` and report the message. |

> **Data use:** on the free tier, Google may use prompts and responses to improve its products; with billing enabled (paid tier) it does not. Use a billing-enabled key for proprietary or sensitive binaries. Local file paths are stripped from the prompt.

---

## 🧪 Testing

Run the comprehensive unit test suite:
```bash
python3 -m pip install -e '.[dev]'
python3 -m unittest discover tests
```
The live Ghidra integration test runs only when `GHIDRA_INSTALL_DIR` is set (it compiles `samples/sample_binary.c` with `gcc`).

---

## 📜 License
Apache-2.0 License.
