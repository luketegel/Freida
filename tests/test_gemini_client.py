"""Tests for the Gemini REST client and cost math."""

import json
import unittest
from unittest.mock import patch

from ghidra_syscall_analyzer.gemini_client import (
    GeminiClient,
    GeminiError,
    ModelPricing,
    pricing_for,
    token_cost,
    usage_cost,
)
from tests.agent_fixtures import ScriptedTransport


class TestPricing(unittest.TestCase):

    def test_default_model_prices(self) -> None:
        self.assertEqual(pricing_for("gemini-3.6-flash"), ModelPricing(input=1.50, cached_input=0.15, output=7.50))

    def test_overrides_and_unknown_models(self) -> None:
        self.assertEqual(pricing_for("gemini-3.6-flash", price_in=0.75).input, 0.75)
        with self.assertRaises(GeminiError):
            pricing_for("gemini-9-ultra")
        custom = pricing_for("gemini-9-ultra", price_in=2.0, price_out=10.0)
        self.assertEqual((custom.input, custom.cached_input, custom.output), (2.0, 0.2, 10.0))

    def test_usage_cost_bills_cached_and_thinking_tokens(self) -> None:
        pricing = pricing_for("gemini-3.6-flash")
        usage = usage_cost({
            "promptTokenCount": 10_000, "cachedContentTokenCount": 4_000,
            "candidatesTokenCount": 1_000, "thoughtsTokenCount": 2_000,
        }, pricing)
        expected = (6_000 * 1.50 + 4_000 * 0.15 + 3_000 * 7.50) / 1_000_000
        self.assertAlmostEqual(usage["cost_usd"], expected)
        self.assertEqual((usage["input_tokens"], usage["output_tokens"], usage["thinking_tokens"]), (10_000, 3_000, 2_000))
        self.assertAlmostEqual(token_cost(1_000_000, 0, pricing), 1.50)


class TestClient(unittest.TestCase):

    def test_requires_api_key(self) -> None:
        with patch.dict("os.environ", {"GEMINI_API_KEY": "", "GOOGLE_API_KEY": ""}):
            with self.assertRaises(GeminiError) as ctx:
                GeminiClient()
        self.assertIn("GEMINI_API_KEY", str(ctx.exception))

    def test_generate_sends_key_header_and_retries_transient_errors(self) -> None:
        transport = ScriptedTransport([(503, b'{"error": {"message": "overloaded"}}'), {"candidates": []}])
        sleeps = []
        client = GeminiClient(api_key="k", transport=transport, sleep=sleeps.append)

        self.assertEqual(client.generate_content("gemini-3.6-flash", {"contents": []}), {"candidates": []})
        self.assertEqual(len(transport.requests), 2)
        self.assertEqual(sleeps, [2.0])
        request = transport.requests[0]
        self.assertTrue(request["url"].endswith("/models/gemini-3.6-flash:generateContent"))
        self.assertEqual(request["headers"]["x-goog-api-key"], "k")
        self.assertNotIn("k", request["url"].split("/")[-1])

    def test_error_message_is_surfaced(self) -> None:
        transport = ScriptedTransport([(400, json.dumps({"error": {"message": "Invalid schema"}}).encode())])
        client = GeminiClient(api_key="k", transport=transport)
        with self.assertRaises(GeminiError) as ctx:
            client.generate_content("gemini-3.6-flash", {})
        self.assertIn("Invalid schema", str(ctx.exception))

    def test_count_tokens_wraps_request(self) -> None:
        transport = ScriptedTransport([{"totalTokens": 8123}])
        client = GeminiClient(api_key="k", transport=transport)
        self.assertEqual(client.count_tokens("gemini-3.6-flash", {"contents": [{"role": "user"}]}), 8123)
        body = transport.requests[0]["body"]
        self.assertEqual(body["generateContentRequest"]["model"], "models/gemini-3.6-flash")
        self.assertTrue(transport.requests[0]["url"].endswith(":countTokens"))


if __name__ == "__main__":
    unittest.main()
