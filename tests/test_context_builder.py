"""Tests for the model context bundle builder."""

import json
import tempfile
import unittest
from pathlib import Path

from ghidra_syscall_analyzer.context_builder import ContextLimits, build_context, write_context
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


if __name__ == "__main__":
    unittest.main()
