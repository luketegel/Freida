# AI Report: Behavioral Overview (Gemini)

`freida-report` turns the context and facts files written by `freida` into an analysis report using the Gemini API (Google AI Studio). The model reads the context, may call up to **3 read-only lookup tools** over the facts file (`get_function`, `get_references`, `search_strings`, `get_data_type`), and writes a structured **Behavioral Overview**: summary, execution flow, behaviors with cited evidence, assessment, and limitations. Every cited function and address is checked against the facts, and anything that can't be found is flagged in the report.

The lookup tools read `binary_facts.json` locally; no Ghidra or MCP server runs during a report.

> **zsh tip:** the commands below have no inline `# comments` because zsh treats them as arguments by default. To paste commented snippets safely, run `setopt interactivecomments` (or add it to `~/.zshrc`).

- [1. Install or update](#1-install-or-update)
- [2. Gemini API key](#2-gemini-api-key)
- [3. Generate a report](#3-generate-a-report)
- [4. Cost](#4-cost)
- [5. See which lookups the model made](#5-see-which-lookups-the-model-made)
- [6. Options](#6-options)
- [Troubleshooting](#troubleshooting)

## 1. Install or update

The `freida-report` command is registered when the package is installed. Re-run this after pulling changes that add commands:

```bash
source .venv/bin/activate
uv pip install -e .
rehash
```

(`python3 -m pip install -e .` works too.) Without installing, the same tool runs as `python -m freida.report_agent`.

## 2. Gemini API key

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

## 3. Generate a report

```bash
freida /path/to/any_binary
freida-report --dry-run
freida-report
```

1. `freida` runs Ghidra and writes `binary_context.json` and `binary_facts.json` in the current folder, whatever the binary is called. (`python analyze_syscalls.py /path/to/any_binary` does the same from a checkout.)
2. `freida-report --dry-run` prints the estimated cost and stops (optional; it costs nothing). The estimate says *counted by Gemini* when the key works.
3. `freida-report` prints the estimate again, generates the report, writes `binary_overview.md` (the report), `binary_overview.pdf` (the same report as a PDF, opening with a TL;DR of the model's verdict and its reason) and `binary_overview.json` (structured result, per-request usage and cost, tool-call trace), and prints the **actual cost**.

Each analysis overwrites the `binary_*` files. To keep several, name them: `freida /path/to/mybin --context-out mybin_context.json --facts-out mybin_facts.json`, then `freida-report mybin_context.json`, which picks up `mybin_facts.json` and writes `mybin_overview.md` and `mybin_overview.pdf`.

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

## 4. Cost

Each run prints an **estimated cost** before generating (exact input size via Gemini's free `countTokens`) and the **actual cost** afterwards (from the API's usage data); both are recorded in `binary_overview.json` and the report footer.

**Estimated cost per run, default model `gemini-3.6-flash`** ($1.50 / 1M input, $7.50 / 1M output incl. thinking; list prices, Oct 2026):

| Binary | Context | No tool calls | 3 tool calls (worst case) |
| :--- | :--- | :--- | :--- |
| `freida/samples/sample_binary` | ~8.5k tokens | ~$0.035 | ~$0.12 |
| Typical program (100–500 functions) | ~50k tokens | ~$0.10 | ~$0.38 |
| Large program (context at its caps) | ~120k tokens | ~$0.20 | ~$0.80 |

Every tool call makes the model send the whole context again, so cost grows with context size × tool calls. Google currently lists a $0.75 / 1M input promotion for gemini-3.6-flash through 2026-12-31, and implicit caching bills repeated context at ~10% of the input price; both only lower the actual cost, but caching is not guaranteed, so estimates ignore it. Cheaper models: `--model gemini-3.5-flash-lite` (about a fifth of the cost) or `gemini-3.1-flash-lite`. Prices are built in per model and can be overridden with `--price-in`, `--price-cached`, `--price-out`.

### When the cost guard stops a run

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

## 5. See which lookups the model made

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

## 6. Options

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

## Troubleshooting

| Message | Fix |
| :--- | :--- |
| `zsh: command not found: freida-report` | Install the package (step 1), or use `python -m freida.report_agent`. |
| `No Gemini API key found` | Set `GEMINI_API_KEY` in this terminal (step 2). |
| `binary_context.json not found` | Run `freida /path/to/binary` first, in the same folder. |
| `Worst-case estimate … exceeds --max-cost` | See [When the cost guard stops a run](#when-the-cost-guard-stops-a-run). |
| `Gemini API error 401/403` | Key invalid or disabled; check it in AI Studio. |
| `Gemini API error 400: …` | The request was rejected; run with `-v` and report the message. |

> **Data use:** on the free tier, Google may use prompts and responses to improve its products; with billing enabled (paid tier) it does not. Use a billing-enabled key for proprietary or sensitive binaries. Local file paths are stripped from the prompt.
