# Model Context and Facts

Each real `freida` run writes two JSON files for an AI model analyzing the binary. `freida-report` reads them (see [AI Report](ai-report.md)), and so can any other model or tool.

* **`binary_context.json`**: the starting context, sized for a model's context window. Sections are relevance-ranked and capped, and file-format metadata that no code uses (load commands, symbol and string tables, loader structures) is left out; `truncated` lists exactly what was cut and names the facts file.
* **`binary_facts.json`**: everything collected, uncapped, including full decompiled code for every function and up to 50 cross-references per string or global. Strings, globals, data types and indicators carry `origin`: `program` or `file_format`.

Change the paths with `--context-out` and `--facts-out`.

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
| `exploration` | How to reach a Ghidra MCP server (launch command or URL, and its tools when known), so a model can query the binary in more detail. |
