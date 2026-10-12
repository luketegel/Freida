"""Tests for the agent's lookup tools, against the real sample facts."""

import json
import unittest

from ghidra_syscall_analyzer.agent_tools import FUNCTION_DECLARATIONS, FactsIndex, cap_result, normalize_address
from tests.agent_fixtures import sample_documents


class TestFactsTools(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        facts, _ = sample_documents()
        cls.index = FactsIndex(facts)

    def test_get_function_by_name_bare_name_and_address(self) -> None:
        by_name = self.index.get_function("_process_execution")
        self.assertIn('_execve("/bin/ls"', by_name["decompiled"])
        self.assertIn({"name": "execve", "severity": "HIGH", "callsite_address": "100000660",
                       "arguments": '"/bin/ls",&local_30,(char **)0x0',
                       "code": '_execve("/bin/ls",&local_30,(char **)0x0);'}, by_name["syscall_findings"])
        self.assertEqual(by_name["callers"], ["entry"])
        self.assertEqual(self.index.get_function("process_execution")["name"], "_process_execution")
        self.assertEqual(self.index.get_function("0x100000608")["name"], "_process_execution")

    def test_unknown_function_suggests_names(self) -> None:
        result = self.index.get_function("process_exec")
        self.assertIn("error", result)
        self.assertIn("_process_execution", result["suggestions"])

    def test_get_references(self) -> None:
        string_refs = self.index.get_references("1000007f6")
        self.assertEqual((string_refs["kind"], string_refs["value"]), ("string", "/bin/ls"))
        self.assertEqual({r["function"] for r in string_refs["referenced_by"]}, {"_process_execution"})
        global_refs = self.index.get_references("100004068")
        self.assertEqual((global_refs["kind"], global_refs["points_to"]), ("global", "s_/bin/ls_1000007f6"))
        function_refs = self.index.get_references("100000608")
        self.assertEqual(function_refs["called_from"], [{"function": "entry", "at": "10000071c"}])
        self.assertIn("error", self.index.get_references("12345"))

    def test_search_strings_includes_origin(self) -> None:
        result = self.index.search_strings("BIN/LS")
        self.assertEqual(result["total_matches"], 1)
        self.assertEqual(result["matches"][0]["referenced_by"], ["_process_execution"])
        dylib = self.index.search_strings("libSystem")["matches"]
        self.assertTrue(all(m["origin"] == "file_format" for m in dylib))
        self.assertIn("error", self.index.search_strings(""))

    def test_get_data_type(self) -> None:
        sockaddr = self.index.get_data_type("sockaddr")
        self.assertEqual([f["name"] for f in sockaddr["fields"]], ["sa_len", "sa_family", "sa_data"])
        self.assertIn("socklen_t", self.index.get_data_type("socklen")["suggestions"])

    def test_known_addresses_include_instructions_inside_functions(self) -> None:
        self.assertTrue(self.index.is_known_address("0x100000640"))
        self.assertTrue(self.index.is_known_address("100000660"))
        self.assertFalse(self.index.is_known_address("deadbeef"))

    def test_run_tool_dispatch_and_errors(self) -> None:
        self.assertEqual(self.index.run_tool("get_function", {"name_or_address": "entry"})["name"], "entry")
        self.assertIn("Unknown tool", self.index.run_tool("delete_files", {})["error"])
        self.assertIn("Bad arguments", self.index.run_tool("get_function", {"nope": 1})["error"])

    def test_declarations_match_tools(self) -> None:
        self.assertEqual({d["name"] for d in FUNCTION_DECLARATIONS},
                         {"get_function", "get_references", "search_strings", "get_data_type"})


class TestHelpers(unittest.TestCase):

    def test_normalize_address(self) -> None:
        self.assertEqual(normalize_address("0x0000100000608"), "100000608")
        self.assertEqual(normalize_address("EXTERNAL:00000001"), "external:1")

    def test_cap_result_trims_decompiled_code(self) -> None:
        capped = cap_result({"name": "big", "decompiled": "x" * 50_000}, max_bytes=2_000)
        self.assertTrue(capped["decompiled_truncated"])
        self.assertLessEqual(len(json.dumps(capped)), 2_000)


if __name__ == "__main__":
    unittest.main()
