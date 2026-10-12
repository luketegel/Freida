"""Shared fixtures for agent tests: real-sample facts/context and a scripted Gemini transport."""

import json
from pathlib import Path
from typing import Any, Dict, List, Tuple

from freida.context_builder import build_context, build_facts
from freida.orchestrator import HeadlessOrchestrator
from freida.pyghidra_collector import PyGhidraCollector

ROOT = Path(__file__).resolve().parent.parent
SAMPLE_BINARY = ROOT / "freida" / "samples" / "sample_binary"
FIXTURE = Path(__file__).resolve().parent / "fixtures" / "ghidra12_macos_arm64_sample_binary.json"


def sample_documents() -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """(facts, context) built from the real Ghidra 12.1.4 run of samples/sample_binary."""
    collector = PyGhidraCollector(target_path=SAMPLE_BINARY)
    collector.load_facts(json.loads(FIXTURE.read_text()))
    orch = HeadlessOrchestrator(SAMPLE_BINARY)
    orch.collect_target_metadata()
    orch._analyze_via_client(collector)
    orch.facts = collector.facts
    orch._add_insights()
    facts = build_facts(orch.metadata, orch.facts, orch.findings)
    context = build_context(orch.metadata, orch.facts, orch.findings, facts_file="sample_binary_facts.json")
    return json.loads(json.dumps(facts)), json.loads(json.dumps(context))


SAMPLE_OVERVIEW: Dict[str, Any] = {
    "summary": "A small test program that writes a file, opens a TCP connection, spawns /bin/ls and maps RWX memory.",
    "execution_flow": "entry calls _perform_direct_syscall, _file_io_operations, _network_operations, "
                      "_process_execution and _memory_manipulation in order.",
    "behaviors": [
        {
            "title": "Spawns /bin/ls via fork and execve",
            "category": "process_execution",
            "severity": "high",
            "description": "Forks and executes /bin/ls -la in the child.",
            "evidence": [
                {"function": "_process_execution", "address": "100000660", "detail": "execve(\"/bin/ls\", ...)"},
            ],
        },
        {
            "title": "Marks memory RWX",
            "category": "memory",
            "severity": "high",
            "description": "mmap then mprotect with PROT_READ|PROT_WRITE|PROT_EXEC.",
            "evidence": [
                {"function": "_memory_manipulation", "address": "0x1000006d4", "detail": "mprotect(..., 7)"},
                {"function": "_inject_payload", "address": "deadbeef", "detail": "hallucinated"},
            ],
        },
    ],
    "assessment": {"classification": "suspicious", "confidence": "medium", "rationale": "Dangerous capabilities."},
    "limitations": ["Static analysis only."],
}


def text_response(payload: Any, usage: Dict[str, int] = None) -> Dict[str, Any]:
    text = payload if isinstance(payload, str) else json.dumps(payload)
    return {
        "candidates": [{
            "content": {"role": "model", "parts": [{"text": text, "thoughtSignature": "sig-final"}]},
            "finishReason": "STOP",
        }],
        "usageMetadata": usage or {"promptTokenCount": 9000, "candidatesTokenCount": 1500, "thoughtsTokenCount": 1000},
    }


def call_response(*calls: Tuple[str, Dict[str, Any]], usage: Dict[str, int] = None) -> Dict[str, Any]:
    parts = []
    for i, (name, args) in enumerate(calls):
        part: Dict[str, Any] = {"functionCall": {"name": name, "args": args, "id": f"call-{i}"}}
        if i == 0:
            part["thoughtSignature"] = "sig-tools"
        parts.append(part)
    return {
        "candidates": [{"content": {"role": "model", "parts": parts}, "finishReason": "STOP"}],
        "usageMetadata": usage or {"promptTokenCount": 9000, "candidatesTokenCount": 200, "thoughtsTokenCount": 800},
    }


class ScriptedTransport:
    """Returns queued (status, body) pairs and records every request."""

    def __init__(self, responses: List[Any]) -> None:
        self.responses = list(responses)
        self.requests: List[Dict[str, Any]] = []

    def __call__(self, url: str, headers: Dict[str, str], body: bytes, timeout: float):
        self.requests.append({"url": url, "headers": headers, "body": json.loads(body)})
        item = self.responses.pop(0)
        if isinstance(item, tuple):
            return item
        return 200, json.dumps(item).encode()

    def generate_bodies(self) -> List[Dict[str, Any]]:
        return [r["body"] for r in self.requests if r["url"].endswith(":generateContent")]
