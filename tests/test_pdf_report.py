"""Tests for the PDF versions of the syscall report and the Behavioral Overview."""

import copy
import tempfile
import unittest
from pathlib import Path

from pypdf import PdfReader

from freida.pdf_report import PdfReportGenerator, assess_syscalls, write_overview_pdf
from freida.syscall_detector import SyscallFinding
from tests.agent_fixtures import SAMPLE_OVERVIEW

METADATA = {
    "file_name": "malicious_sample.elf",
    "absolute_path": "/tmp/malicious_sample.elf",
    "file_size_formatted": "12.50 KB",
    "file_size_bytes": 12800,
    "sha256": "112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00",
    "md5": "00112233445566778899aabbccddeeff",
    "file_type": "Linux ELF (64-bit)",
    "architecture": "x86:LE:64:default",
    "analysis_time": "2026-10-12 12:00:00 UTC",
    "backend": "pyghidra",
}


def finding(name, category, severity, function, snippet, arguments, callsite=None):
    return SyscallFinding(
        name=name, category=category, description="", severity=severity, detection_type="LIBC_WRAPPER",
        function_name=function, address="0x401120", line_number=3, code_snippet=snippet,
        arguments=arguments, callsite_address=callsite,
    )


def pdf_text(path: Path) -> str:
    return "\n".join(page.extract_text() for page in PdfReader(str(path)).pages)


class TestSyscallPdfReport(unittest.TestCase):

    def test_report_sections_and_content(self) -> None:
        findings = [
            finding("execve", "Process & Execution", "HIGH", "spawn_shell", 'execve("/bin/sh", args, NULL);',
                    '"/bin/sh", args, NULL', callsite="0x401134"),
            finding("socket", "Networking & Sockets", "MEDIUM", "init_c2", "int s = socket(2, 1, 0);", "2, 1, 0"),
        ]
        decompiled = {"spawn_shell": 'void spawn_shell() {\n    execve("/bin/sh", args, NULL);\n}'}
        with tempfile.TemporaryDirectory() as tmp:
            out = PdfReportGenerator(METADATA, findings, decompiled).write_to_file(Path(tmp) / "sub" / "r.pdf")
            self.assertTrue(out.read_bytes().startswith(b"%PDF"))
            content = pdf_text(out)
            reader = PdfReader(str(out))
            self.assertEqual(reader.metadata.title, "System Call Analysis Report: malicious_sample.elf")

        for expected in ("System Call Analysis Report", "malicious_sample.elf", METADATA["sha256"],
                         "Analysis Dashboard", "System Call Categories", "System Calls Inventory",
                         "Process & Execution", "Networking & Sockets", "execve", "0x401134",
                         "Decompiled Evidence", "Full decompiled function", "PyGhidra", "Page 1"):
            self.assertIn(expected, content)

    def test_tldr_verdict_at_the_top(self) -> None:
        findings = [
            finding("execve", "Process & Execution", "HIGH", "spawn_shell", "execve();", ""),
            finding("socket", "Networking & Sockets", "MEDIUM", "init_c2", "socket();", ""),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            content = pdf_text(PdfReportGenerator(METADATA, findings).write_to_file(Path(tmp) / "r.pdf"))
        tldr = content.index("TL;DR")
        self.assertLess(tldr, content.index("Suspicious"))
        self.assertLess(content.index("Suspicious"), content.index("Target Binary Information"))
        self.assertIn("not a malware scan", content)

    def test_assessment_rules(self) -> None:
        def verdict(*specs):
            return assess_syscalls([finding(n, c, s, "f", "", "") for n, c, s in specs])["verdict"]

        self.assertEqual(verdict(), "Unknown")
        self.assertEqual(verdict(("read", "File I/O", "LOW"), ("mmap", "Memory Management", "MEDIUM")),
                         "Likely Benign")
        self.assertEqual(verdict(("mprotect", "Memory Management", "HIGH")), "Needs Review")
        self.assertEqual(verdict(("mprotect", "Memory Management", "HIGH"),
                                 ("direct_syscall", "Direct Syscall", "HIGH")), "Suspicious")
        self.assertEqual(verdict(("execve", "Process & Execution", "HIGH"),
                                 ("connect", "Networking & Sockets", "HIGH")), "Suspicious")
        self.assertEqual(verdict(("VirtualAllocEx", "Memory Management", "CRITICAL")), "Suspicious")
        self.assertEqual(verdict(("WriteProcessMemory", "Memory Management", "CRITICAL"),
                                 ("CreateRemoteThread", "Process & Execution", "CRITICAL")), "Malicious")

    def test_no_findings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            content = pdf_text(PdfReportGenerator(METADATA, []).write_to_file(Path(tmp) / "r.pdf"))
        self.assertIn("No system calls detected", content)
        self.assertIn("too little to judge", content)
        self.assertIn("Low Risk", content)

    def test_markup_and_long_code_from_the_binary_are_rendered_safely(self) -> None:
        hostile = '<font color="red">&nbsp;</b> & "quotes"'
        long_body = "\n".join(f"    x{i} = call_{i}({'a' * 200});" for i in range(200))
        findings = [finding("open", "File I/O", "MEDIUM", "f<&>", f'open("{hostile}", 0);', hostile)]
        with tempfile.TemporaryDirectory() as tmp:
            out = PdfReportGenerator(METADATA, findings, {"f<&>": long_body}).write_to_file(Path(tmp) / "r.pdf")
            content = pdf_text(out)
        self.assertIn("f<&>", content)
        self.assertIn('<font color="red">', content)
        self.assertIn("lines truncated", content)


class TestOverviewPdf(unittest.TestCase):
    TARGET = {"file_name": "sample_binary", "sha256": "ab" * 32, "architecture": "AARCH64:LE:64:AppleSilicon"}

    def result(self, overview):
        return {
            "model": "gemini-3.6-flash",
            "overview": overview,
            "finish_reason": "STOP",
            "raw_text": "not json <oops>",
            "usage": {"total": {"requests": 2, "tool_calls": 1, "input_tokens": 9000, "cached_tokens": 0,
                                "output_tokens": 2500, "thinking_tokens": 800, "cost_usd": 0.0321}},
            "estimate": {"input_tokens": 8500, "counted": True, "min_cost_usd": 0.03, "max_cost_usd": 0.12},
        }

    def test_overview_pdf(self) -> None:
        overview = copy.deepcopy(SAMPLE_OVERVIEW)
        overview["behaviors"][0]["evidence"][0]["verified"] = False
        with tempfile.TemporaryDirectory() as tmp:
            content = pdf_text(write_overview_pdf(self.result(overview), self.TARGET, Path(tmp) / "o.pdf"))
        for expected in ("Analysis Report", "sample_binary", "Behavioral Overview", "Execution Flow",
                         "Observed Behaviors", overview["behaviors"][0]["title"], "unverified",
                         "gemini-3.6-flash", "cost $0.0321"):
            self.assertIn(expected, content)
        tldr = content.index("TL;DR")
        rationale = content.index(overview["assessment"]["rationale"][:30])
        self.assertLess(tldr, content.index("Suspicious"))
        self.assertLess(rationale, content.index(overview["summary"][:40]))
        self.assertLess(content.index(overview["summary"][:40]), content.index("Execution Flow"))

    def test_overview_pdf_without_structured_answer(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            content = pdf_text(write_overview_pdf(self.result(None), self.TARGET, Path(tmp) / "o.pdf"))
        self.assertIn("did not return a valid structured overview", content)
        self.assertIn("not json <oops>", content)


if __name__ == "__main__":
    unittest.main()
