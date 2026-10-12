"""Tests for the model context bundle builder."""

import json
import tempfile
import unittest
from pathlib import Path

from ghidra_syscall_analyzer.context_builder import ContextLimits, build_context, build_facts, write_context
from ghidra_syscall_analyzer.syscall_detector import SyscallDetector


def make_facts(num_helpers: int = 3, num_strings: int = 5) -> dict:
    functions = [
        {
            "name": "main",
            "address": "00101100",
            "size": 64,
            "callees": ["helper_0"],
            "callsites": [{"to": "helper_0", "at": "00101110"}],
            "decompiled": "int main(void) {\n  helper_0();\n  return 0;\n}",
        }
    ]
    for i in range(num_helpers):
        functions.append({
            "name": f"helper_{i}",
            "address": f"0010120{i}",
            "size": 32,
            "callees": ["execve"],
            "callsites": [{"to": "execve", "at": f"0010121{i}"}],
            "decompiled": "\n".join(["void helper() {"] + ["  x = 1;"] * 10 + ["  execve(\"/bin/sh\", 0, 0);", "}"]),
        })
    functions.append({"name": "quiet", "address": "00101300", "size": 8, "decompiled": "void quiet(void) {\n}"})
    return {
        "program": {"name": "sample", "language_id": "x86:LE:64:default", "entry_points": []},
        "imports": [{"name": "execve", "library": "libc.so.6", "address": "EXTERNAL:00000001"}],
        "exports": [],
        "functions": functions,
        "strings": [{"address": f"0010200{i}", "value": "s" * (10 + i)} for i in range(num_strings)],
        "limits": {"functions_total": len(functions) + 2},
    }


class TestContextBuilder(unittest.TestCase):

    def setUp(self) -> None:
        detector = SyscallDetector()
        self.facts = make_facts()
        self.findings = []
        for fn in self.facts["functions"]:
            self.findings.extend(detector.analyze_decompiled_function(fn["name"], fn["decompiled"], fn["address"]))
        self.metadata = {"file_name": "sample", "sha256": "ab" * 32, "backend": "pyghidra", "absolute_path": "/x"}

    def test_bundle_shape(self) -> None:
        ctx = build_context(self.metadata, self.facts, self.findings, exploration={"protocol": "mcp"})

        for key in ("schema_version", "target", "program", "imports", "exports", "syscall_summary",
                    "syscall_findings", "functions", "strings", "truncated", "exploration"):
            self.assertIn(key, ctx)
        self.assertEqual(ctx["target"]["sha256"], "ab" * 32)
        self.assertNotIn("absolute_path", ctx["target"])
        self.assertIn("execve", ctx["syscall_summary"]["unique"])
        self.assertEqual(ctx["exploration"]["protocol"], "mcp")

        by_name = {f["name"]: f for f in ctx["functions"]}
        self.assertEqual(len(by_name), len(self.facts["functions"]))
        self.assertIn("decompiled", by_name["main"])  # entry function
        self.assertIn("decompiled", by_name["helper_0"])  # has syscall findings
        self.assertNotIn("decompiled", by_name["quiet"])
        self.assertEqual(by_name["helper_0"]["syscalls"], ["execve"])
        self.assertEqual(by_name["main"]["callsites"][0]["at"], "00101110")
        self.assertEqual(ctx["truncated"]["functions_not_collected"], 2)

    def test_limits_are_applied_and_reported(self) -> None:
        limits = ContextLimits(max_decompiled_functions=2, max_decompiled_lines=5, max_strings=3, max_string_length=11)
        ctx = build_context(self.metadata, self.facts, self.findings, limits=limits)

        decompiled = [f for f in ctx["functions"] if "decompiled" in f]
        self.assertEqual(len(decompiled), 2)
        self.assertEqual(decompiled[0]["name"], "main")  # entry points come first
        self.assertEqual(len(ctx["truncated"]["decompiled_omitted"]), 2)
        self.assertIn("helper_0", ctx["truncated"]["decompiled_line_capped"])
        self.assertLessEqual(len(decompiled[1]["decompiled"].splitlines()), 5)

        self.assertEqual(len(ctx["strings"]), 3)
        self.assertEqual(ctx["truncated"]["strings_omitted"], 2)
        self.assertTrue(ctx["strings"][2]["truncated"])
        self.assertEqual(len(ctx["strings"][2]["value"]), 11)

    def test_write_context_is_valid_json(self) -> None:
        ctx = build_context(self.metadata, self.facts, self.findings)
        with tempfile.TemporaryDirectory() as tmp:
            path = write_context(ctx, Path(tmp) / "nested" / "ctx.json")
            loaded = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(loaded["schema_version"], ctx["schema_version"])


def add_extended_facts(facts: dict) -> dict:
    ref = lambda fn: [{"function": fn, "at": "00101110", "ref_type": "READ"}]
    facts["strings"] = [
        {"address": "00102000", "value": "__TEXT", "referenced_by": []},
        {"address": "00102010", "value": "/bin/sh", "referenced_by": ref("helper_0") + ref("helper_1")},
        {"address": "00102020", "value": "/tmp/x", "referenced_by": ref("main")},
    ]
    facts["globals"] = [
        {"address": "00103000", "label": "unused", "type": "int", "size": 4, "referenced_by": []},
        {"address": "00103008", "label": "PTR_s__bin_sh", "type": "pointer", "size": 8, "points_to": "s_/bin/sh",
         "referenced_by": ref("helper_0")},
    ]
    facts["data_types"] = [
        {"name": "misc_t", "kind": "struct", "size": 4, "used_by": ["quiet", "main"],
         "fields": [{"offset": 0, "name": "x", "type": "int", "size": 4}]},
        {"name": "big_t", "kind": "struct", "size": 400, "used_by": ["helper_0"],
         "fields": [{"offset": i * 4, "name": f"f{i}", "type": "int", "size": 4} for i in range(100)]},
    ]
    facts["indicators"] = [{"kind": "unix_path", "value": f"/tmp/{i}", "string_address": "0", "referenced_by": []}
                           for i in range(5)]
    facts["memory_map"] = [{"name": ".text", "permissions": "r-x", "entropy": 6.1}]
    facts["hardening"] = {"format": "ELF", "pie": True, "stack_canary": True}
    facts["program_metadata"] = {"Compiler ID": "gcc"}
    for fn in facts["functions"]:
        fn["callers"] = ["main"] if fn["name"].startswith("helper") else []
        fn["signature"] = f"void {fn['name']}(void)"
    return facts


class TestExtendedSections(unittest.TestCase):

    def setUp(self) -> None:
        detector = SyscallDetector()
        self.facts = add_extended_facts(make_facts())
        self.findings = []
        for fn in self.facts["functions"]:
            self.findings.extend(detector.analyze_decompiled_function(fn["name"], fn["decompiled"], fn["address"]))
        self.metadata = {"file_name": "sample", "backend": "pyghidra"}

    def test_context_ranks_referenced_items_first(self) -> None:
        ctx = build_context(self.metadata, self.facts, self.findings, facts_file="sample_facts.json")

        self.assertEqual([s["value"] for s in ctx["strings"]], ["/bin/sh", "/tmp/x", "__TEXT"])
        self.assertEqual(ctx["strings"][0]["referenced_by"], ["helper_0", "helper_1"])
        self.assertEqual([g["label"] for g in ctx["globals"]], ["PTR_s__bin_sh", "unused"])
        self.assertEqual(ctx["globals"][0]["points_to"], "s_/bin/sh")
        # big_t is used by a function with syscall findings, so it outranks the more widely used misc_t.
        self.assertEqual([t["name"] for t in ctx["data_types"]], ["big_t", "misc_t"])
        self.assertEqual(ctx["schema_version"], 2)
        self.assertEqual(ctx["truncated"]["full_facts_file"], "sample_facts.json")
        self.assertEqual(ctx["hardening"]["pie"], True)
        self.assertEqual(ctx["memory_map"][0]["entropy"], 6.1)
        helper = next(f for f in ctx["functions"] if f["name"] == "helper_0")
        self.assertEqual((helper["callers"], helper["signature"]), (["main"], "void helper_0(void)"))

    def test_context_caps_are_reported(self) -> None:
        limits = ContextLimits(max_strings=1, max_globals=1, max_data_types=1, max_fields_per_type=10, max_indicators=2)
        ctx = build_context(self.metadata, self.facts, self.findings, limits=limits)

        self.assertEqual(len(ctx["strings"]), 1)
        self.assertEqual(len(ctx["data_types"][0]["fields"]), 10)
        self.assertEqual(ctx["data_types"][0]["fields_omitted"], 90)
        truncated = ctx["truncated"]
        self.assertEqual(
            (truncated["strings_omitted"], truncated["globals_omitted"], truncated["data_types_omitted"],
             truncated["indicators_omitted"]),
            (2, 1, 1, 3),
        )

    def test_facts_are_uncapped_with_all_decompiled_code(self) -> None:
        facts = build_facts(self.metadata, self.facts, self.findings, exploration={"protocol": "mcp"})

        self.assertEqual(len(facts["strings"]), 3)
        self.assertEqual(len(facts["data_types"][1]["fields"]), 100)
        self.assertEqual(len(facts["indicators"]), 5)
        self.assertTrue(all("decompiled" in f for f in facts["functions"]))
        self.assertEqual(facts["strings"][1]["referenced_by"][0]["ref_type"], "READ")
        self.assertNotIn("truncated", facts)

    def test_file_format_items_and_empty_strings_stay_out_of_context(self) -> None:
        self.facts["strings"].append({"address": "00109000", "value": "__LINKEDIT", "origin": "file_format"})
        self.facts["strings"].append({"address": "00102030", "value": "", "origin": "program"})
        self.facts["data_types"].append({"name": "mach_header", "kind": "struct", "origin": "file_format"})
        ctx = build_context(self.metadata, self.facts, self.findings)

        self.assertNotIn("__LINKEDIT", [s["value"] for s in ctx["strings"]])
        self.assertNotIn("", [s["value"] for s in ctx["strings"]])
        self.assertNotIn("mach_header", [t["name"] for t in ctx["data_types"]])
        self.assertEqual(ctx["truncated"]["file_format_omitted"]["strings"], 1)
        self.assertEqual(ctx["truncated"]["file_format_omitted"]["data_types"], 1)
        self.assertEqual(ctx["truncated"]["empty_strings_omitted"], 1)
        self.assertEqual(len(build_facts(self.metadata, self.facts, self.findings)["strings"]), 5)

    def test_missing_sections_default_empty(self) -> None:
        ctx = build_context(self.metadata, make_facts(), self.findings)
        for key in ("globals", "data_types", "indicators", "memory_map"):
            self.assertEqual(ctx[key], [])
        self.assertEqual(ctx["hardening"], {})


if __name__ == "__main__":
    unittest.main()
