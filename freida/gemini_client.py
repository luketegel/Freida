"""Gemini API Client.

Minimal REST client for the Gemini Developer API (Google AI Studio keys):
`generateContent` and `countTokens` over `urllib`, with retries on transient
errors, plus the per-model pricing used to estimate and report run cost.
"""

from __future__ import annotations

import json
import logging
import os
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger("freida.gemini_client")

GEMINI_API_BASE = "https://generativelanguage.googleapis.com/v1beta"
RETRY_STATUSES = {429, 500, 503}

# (status, body) = transport(url, headers, body_bytes, timeout)
Transport = Callable[[str, dict[str, str], bytes, float], tuple[int, bytes]]


class GeminiError(Exception):
    """Raised for Gemini API errors, missing credentials, or unusable responses."""
    pass


@dataclass(frozen=True)
class ModelPricing:
    """USD per 1M tokens. Output includes thinking tokens."""
    input: float
    cached_input: float
    output: float


# Standard paid-tier list prices (Gemini Developer API pricing page, Oct 2026).
# gemini-3.6-flash shows a $0.75 input promotion through 2026-12-31; the list price is used
# so estimates stay conservative. Override with --price-in / --price-cached / --price-out.
MODEL_PRICING: dict[str, ModelPricing] = {
    "gemini-3.6-flash": ModelPricing(input=1.50, cached_input=0.15, output=7.50),
    "gemini-3.5-flash-lite": ModelPricing(input=0.30, cached_input=0.03, output=2.50),
    "gemini-3.1-flash-lite": ModelPricing(input=0.25, cached_input=0.025, output=1.50),
}


def pricing_for(
    model: str,
    price_in: float | None = None,
    price_cached: float | None = None,
    price_out: float | None = None,
) -> ModelPricing:
    """Pricing for a model, with optional per-field overrides; unknown models require overrides."""
    base = MODEL_PRICING.get(model)
    if base is None and (price_in is None or price_out is None):
        raise GeminiError(
            f"No built-in pricing for model '{model}'. Pass --price-in and --price-out (USD per 1M tokens)."
        )
    base = base or ModelPricing(input=price_in or 0.0, cached_input=(price_in or 0.0) / 10, output=price_out or 0.0)
    return ModelPricing(
        input=price_in if price_in is not None else base.input,
        cached_input=price_cached if price_cached is not None else base.cached_input,
        output=price_out if price_out is not None else base.output,
    )


def token_cost(input_tokens: int, output_tokens: int, pricing: ModelPricing, cached_tokens: int = 0) -> float:
    """Cost in USD; `input_tokens` includes any cached tokens, which are billed at the cached rate."""
    uncached = max(input_tokens - cached_tokens, 0)
    return (
        uncached * pricing.input + cached_tokens * pricing.cached_input + output_tokens * pricing.output
    ) / 1_000_000


def usage_cost(usage: dict[str, Any], pricing: ModelPricing) -> dict[str, Any]:
    """Token counts and cost for one response's `usageMetadata`."""
    input_tokens = int(usage.get("promptTokenCount", 0)) + int(usage.get("toolUsePromptTokenCount", 0))
    cached_tokens = int(usage.get("cachedContentTokenCount", 0))
    output_tokens = int(usage.get("candidatesTokenCount", 0)) + int(usage.get("thoughtsTokenCount", 0))
    return {
        "input_tokens": input_tokens,
        "cached_tokens": cached_tokens,
        "output_tokens": output_tokens,
        "thinking_tokens": int(usage.get("thoughtsTokenCount", 0)),
        "cost_usd": token_cost(input_tokens, output_tokens, pricing, cached_tokens),
    }


def _urllib_transport(url: str, headers: dict[str, str], body: bytes, timeout: float) -> tuple[int, bytes]:
    request = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except urllib.error.URLError as e:
        raise GeminiError(f"Could not reach the Gemini API: {e.reason}") from e


class GeminiClient:
    """Calls the Gemini Developer API with an AI Studio API key."""

    def __init__(
        self,
        api_key: str | None = None,
        base_url: str = GEMINI_API_BASE,
        timeout: float = 180.0,
        max_retries: int = 2,
        retry_backoff: float = 2.0,
        transport: Transport | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.api_key = api_key or os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
        if not self.api_key:
            raise GeminiError("No Gemini API key found. Create one in Google AI Studio and set GEMINI_API_KEY.")
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.max_retries = max_retries
        self.retry_backoff = retry_backoff
        self.transport = transport or _urllib_transport
        self.sleep = sleep

    def _post(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        url = f"{self.base_url}/{path}"
        headers = {"Content-Type": "application/json", "x-goog-api-key": self.api_key}
        payload = json.dumps(body).encode("utf-8")

        for attempt in range(self.max_retries + 1):
            status, raw = self.transport(url, headers, payload, self.timeout)
            if status == 200:
                try:
                    return json.loads(raw.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError) as e:
                    raise GeminiError(f"Gemini API returned invalid JSON: {e}") from e
            if status in RETRY_STATUSES and attempt < self.max_retries:
                delay = self.retry_backoff * (2 ** attempt)
                logger.warning("Gemini API returned %d; retrying in %.0fs", status, delay)
                self.sleep(delay)
                continue
            raise GeminiError(f"Gemini API error {status}: {self._error_message(raw)}")
        raise GeminiError("Gemini API request failed after retries")  # pragma: no cover

    @staticmethod
    def _error_message(raw: bytes) -> str:
        try:
            return json.loads(raw.decode("utf-8"))["error"]["message"]
        except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError):
            return raw.decode("utf-8", errors="replace")[:500]

    def generate_content(self, model: str, request: dict[str, Any]) -> dict[str, Any]:
        return self._post(f"models/{model}:generateContent", request)

    def count_tokens(self, model: str, request: dict[str, Any]) -> int:
        """Input tokens a generateContent request would use (the countTokens call itself is free)."""
        body = {"generateContentRequest": {"model": f"models/{model}", **request}}
        return int(self._post(f"models/{model}:countTokens", body).get("totalTokens", 0))
