"""Tests for the Behavioral Overview agent loop, cost handling, validation and CLI (offline, scripted Gemini)."""

import copy
import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from ghidra_syscall_analyzer.agent_tools import FactsIndex
from ghidra_syscall_analyzer.gemini_client import GeminiClient, pricing_for, token_cost
from ghidra_syscall_analyzer.report_agent import (
    EST_FINAL_OUTPUT,
    OverviewAgent,
    build_initial_contents,
    estimate_cost,
    main,
    parse_overview,
    prepare_context,
    render_markdown,
    validate_evidence,
)
from tests.agent_fixtures import SAMPLE_OVERVIEW, ScriptedTransport, call_response, sample_documents, text_response


class AgentTestCase(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        cls.facts, cls.context = sample_documents()

    def agent(self, responses, **kwargs):
        transport = ScriptedTransport(responses)
        client = GeminiClient(api_key="test-key", transport=transport, sleep=lambda _: None)
        agent = OverviewAgent(client, self.context, FactsIndex(self.facts), **kwargs)
        return agent, transport


class TestPrompt(AgentTestCase):

    def test_context_is_compact_delimited_and_private_paths_removed(self) -> None:
        context = copy.deepcopy(self.context)
        context["program_metadata"]["Executable Location"] = "/Users/someone/secret/sample_binary"
        text = build_initial_contents(context)[0]["parts"][0]["text"]
        self.assertIn("<binary_context>\n{", text)
        self.assertNotIn("/Users/someone", text)
        self.assertNotIn('"exploration"', text)
        self.assertNotIn(": ", text.split("<binary_context>")[1][:200])  # compact separators
        self.assertNotIn("full_facts_file", json.dumps(prepare_context(context)))


class TestCostEstimate(AgentTestCase):

    def test_estimate_range(self) -> None:
        pricing = pricing_for("gemini-3.6-flash")
        costs = estimate_cost(10_000, 3, pricing)
        self.assertAlmostEqual(costs["min"], token_cost(10_000, EST_FINAL_OUTPUT, pricing))
        # 4 requests growing by 2,700 tokens each, 3 tool turns of 1,200 output plus the final answer.
        self.assertAlmostEqual(costs["max"], token_cost(4 * 10_000 + 2_700 * 6, 3 * 1_200 + 3_000, pricing))
        self.assertAlmostEqual(estimate_cost(10_000, 0, pricing)["max"], costs["min"])

    def test_estimate_uses_count_tokens(self) -> None:
        agent, transport = self.agent([{"totalTokens": 8500}])
        estimate = agent.estimate()
        self.assertTrue(estimate.counted)
        self.assertEqual(estimate.input_tokens, 8500)
        counted_request = transport.requests[0]["body"]["generateContentRequest"]
        self.assertEqual(counted_request["toolConfig"]["functionCallingConfig"]["mode"], "AUTO")

    def test_estimate_falls_back_when_count_tokens_fails(self) -> None:
        agent, _ = self.agent([(403, b'{"error": {"message": "forbidden"}}')])
        estimate = agent.estimate()
        self.assertFalse(estimate.counted)
        self.assertGreater(estimate.input_tokens, 1000)


class TestAgentLoop(AgentTestCase):

    def test_direct_answer_without_tools(self) -> None:
        agent, transport = self.agent([text_response(SAMPLE_OVERVIEW)])
        result = agent.run()

        self.assertEqual(result.overview["assessment"]["classification"], "suspicious")
        self.assertEqual(result.totals["requests"], 1)
        self.assertEqual(result.totals["tool_calls"], 0)
        request = transport.generate_bodies()[0]
        self.assertEqual(request["generationConfig"]["responseMimeType"], "application/json")
        self.assertEqual(request["generationConfig"]["thinkingConfig"], {"thinkingLevel": "low"})
        self.assertIn("at most 3 tool calls", request["systemInstruction"]["parts"][0]["text"])
        expected = token_cost(9000, 2500, pricing_for("gemini-3.6-flash"))
        self.assertAlmostEqual(result.totals["cost_usd"], expected)

    def test_tool_calls_then_answer_preserve_thought_signatures(self) -> None:
        agent, transport = self.agent([
            call_response(("get_function", {"name_or_address": "_process_execution"})),
            call_response(("search_strings", {"query": "/tmp"})),
            text_response(SAMPLE_OVERVIEW),
        ])
        result = agent.run()

        self.assertEqual([c["name"] for c in result.tool_calls], ["get_function", "search_strings"])
        self.assertEqual(result.totals["tool_calls"], 2)
        second = transport.generate_bodies()[1]["contents"]
        self.assertEqual(second[1]["parts"][0]["thoughtSignature"], "sig-tools")  # model turn sent back unchanged
        function_response = second[2]["parts"][0]["functionResponse"]
        self.assertEqual((function_response["name"], function_response["id"]), ("get_function", "call-0"))
        self.assertIn("_execve", function_response["response"]["decompiled"])

    def test_tool_budget_is_enforced(self) -> None:
        agent, transport = self.agent([
            call_response(*[("get_function", {"name_or_address": n}) for n in
                            ("entry", "_file_io_operations", "_network_operations", "_process_execution", "_memory_manipulation")]),
            text_response(SAMPLE_OVERVIEW),
        ])
        result = agent.run()

        self.assertEqual(result.totals["tool_calls"], 3)
        self.assertEqual(sum(1 for c in result.tool_calls if c["skipped"]), 2)
        bodies = transport.generate_bodies()
        responses = bodies[1]["contents"][2]["parts"]
        self.assertEqual(len(responses), 5)  # every call gets a response, over-budget ones an error
        self.assertIn("budget exhausted", responses[4]["functionResponse"]["response"]["error"])
        self.assertEqual(bodies[1]["toolConfig"]["functionCallingConfig"]["mode"], "NONE")

    def test_spend_guard_stops_tool_use(self) -> None:
        agent, transport = self.agent([
            call_response(("get_function", {"name_or_address": "entry"})),
            text_response(SAMPLE_OVERVIEW),
        ], max_cost=0.03)
        result = agent.run()
        self.assertIsNotNone(result.overview)
        self.assertEqual(transport.generate_bodies()[1]["toolConfig"]["functionCallingConfig"]["mode"], "NONE")
        self.assertFalse(result.turns[1]["tools_allowed"])

    def test_invalid_json_answer_is_kept_raw(self) -> None:
        agent, _ = self.agent([text_response("I think this program is fine.")])
        result = agent.run()
        self.assertIsNone(result.overview)
        markdown = render_markdown(result, self.context["target"])
        self.assertIn("did not return a valid structured overview", markdown)
        self.assertIn("I think this program is fine.", markdown)


class TestValidationAndRendering(AgentTestCase):

    def test_unverified_evidence_is_flagged(self) -> None:
        overview = copy.deepcopy(SAMPLE_OVERVIEW)
        unverified = validate_evidence(overview, FactsIndex(self.facts))
        self.assertEqual(unverified, 1)
        flags = [e["verified"] for b in overview["behaviors"] for e in b["evidence"]]
        self.assertEqual(flags, [True, True, False])

    def test_markdown_report(self) -> None:
        agent, _ = self.agent([text_response(SAMPLE_OVERVIEW)])
        result = agent.run()
        validate_evidence(result.overview, FactsIndex(self.facts))
        markdown = render_markdown(result, self.context["target"])

        for expected in ("## Behavioral Overview", "**Assessment:** Suspicious (confidence: medium)",
                         "### Execution Flow", "#### 1. Spawns /bin/ls via fork and execve", "🟠 HIGH",
                         "`_process_execution` @ `100000660`", "unverified", "### Limitations", "cost $"):
            self.assertIn(expected, markdown)

    def test_parse_overview_accepts_fenced_json(self) -> None:
        self.assertEqual(parse_overview("```json\n{\"summary\": \"x\"}\n```"), {"summary": "x"})
        self.assertIsNone(parse_overview("[1, 2]"))


class TestCli(AgentTestCase):

    def write_inputs(self, tmp: str) -> Path:
        context_path = Path(tmp) / "sample_binary_context.json"
        context_path.write_text(json.dumps(self.context))
        (Path(tmp) / "sample_binary_facts.json").write_text(json.dumps(self.facts))
        return context_path

    def test_dry_run_without_api_key(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, patch.dict("os.environ", {"GEMINI_API_KEY": "", "GOOGLE_API_KEY": ""}):
            out = io.StringIO()
            with redirect_stdout(out):
                code = main([str(self.write_inputs(tmp)), "--dry-run"])
            self.assertEqual(code, 0)
            self.assertIn("Estimated cost: $", out.getvalue())
            self.assertIn("up to 3 tool call(s)", out.getvalue())
            self.assertFalse((Path(tmp) / "sample_binary_overview.md").exists())

    def test_full_run_writes_report_and_reports_cost(self) -> None:
        transport = ScriptedTransport([
            {"totalTokens": 8500},
            call_response(("get_function", {"name_or_address": "_memory_manipulation"})),
            text_response(SAMPLE_OVERVIEW),
        ])
        with tempfile.TemporaryDirectory() as tmp:
            context_path = self.write_inputs(tmp)
            out = io.StringIO()
            with patch("ghidra_syscall_analyzer.report_agent.GeminiClient",
                       lambda: GeminiClient(api_key="k", transport=transport)), redirect_stdout(out):
                code = main([str(context_path)])

            self.assertEqual(code, 0)
            report = (Path(tmp) / "sample_binary_overview.md").read_text()
            data = json.loads((Path(tmp) / "sample_binary_overview.json").read_text())
            self.assertIn("## Behavioral Overview", report)
            self.assertEqual(data["usage"]["total"]["tool_calls"], 1)
            self.assertEqual(data["unverified_evidence"], 1)
            self.assertEqual(data["estimate"]["input_tokens"], 8500)
            self.assertIn("Actual cost: $", out.getvalue())
            pdf = Path(tmp) / "sample_binary_overview.pdf"
            self.assertTrue(pdf.read_bytes().startswith(b"%PDF"))
            self.assertIn(str(pdf.resolve()), out.getvalue())

    def test_defaults_to_binary_context_and_facts_in_current_folder(self) -> None:
        transport = ScriptedTransport([{"totalTokens": 8500}, text_response(SAMPLE_OVERVIEW)])
        previous = os.getcwd()
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "binary_context.json").write_text(json.dumps(self.context))
            Path(tmp, "binary_facts.json").write_text(json.dumps(self.facts))
            os.chdir(tmp)
            try:
                out = io.StringIO()
                with patch("ghidra_syscall_analyzer.report_agent.GeminiClient",
                           lambda: GeminiClient(api_key="k", transport=transport)), redirect_stdout(out):
                    code = main([])
                self.assertEqual(code, 0)
                self.assertTrue(Path(tmp, "binary_overview.md").exists())
                self.assertTrue(Path(tmp, "binary_overview.json").exists())
                self.assertTrue(Path(tmp, "binary_overview.pdf").exists())
                self.assertIn("up to 3 tool call(s)", out.getvalue())  # facts found, so tools are enabled
            finally:
                os.chdir(previous)

    def test_missing_context_explains_next_step(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = io.StringIO()
            with redirect_stdout(out):
                code = main([str(Path(tmp) / "binary_context.json")])
        self.assertEqual(code, 2)
        self.assertIn("Analyze a binary first", out.getvalue())

    def test_max_cost_aborts_before_spending(self) -> None:
        transport = ScriptedTransport([{"totalTokens": 120_000}])
        with tempfile.TemporaryDirectory() as tmp:
            out = io.StringIO()
            with patch("ghidra_syscall_analyzer.report_agent.GeminiClient",
                       lambda: GeminiClient(api_key="k", transport=transport)), redirect_stdout(out):
                code = main([str(self.write_inputs(tmp)), "--max-cost", "0.10"])
            self.assertEqual(code, 3)
            self.assertIn("exceeds --max-cost", out.getvalue())
            self.assertEqual(len(transport.generate_bodies()), 0)


if __name__ == "__main__":
    unittest.main()
