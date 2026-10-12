"""Tests for MarkdownReportGenerator."""

import tempfile
import unittest
from pathlib import Path

from freida.report_generator import MarkdownReportGenerator
from freida.syscall_detector import SyscallFinding


class TestMarkdownReportGenerator(unittest.TestCase):

    def test_report_generation_structure(self) -> None:
        metadata = {
            "file_name": "malicious_sample.elf",
            "absolute_path": "/tmp/malicious_sample.elf",
            "file_size_formatted": "12.50 KB",
            "file_size_bytes": 12800,
            "sha256": "112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00",
            "md5": "00112233445566778899aabbccddeeff",
            "file_type": "Linux ELF (64-bit)",
            "architecture": "x86:LE:64:default",
            "analysis_time": "2026-10-12 12:00:00 UTC",
        }

        findings = [
            SyscallFinding(
                name="execve",
                category="Process & Execution",
                description="Execute binary program",
                severity="HIGH",
                detection_type="LIBC_WRAPPER",
                function_name="spawn_shell",
                address="0x401120",
                line_number=14,
                code_snippet='execve("/bin/sh", args, NULL);',
                arguments='"/bin/sh", args, NULL',
            ),
            SyscallFinding(
                name="socket",
                category="Networking & Sockets",
                description="Create communication endpoint",
                severity="MEDIUM",
                detection_type="LIBC_WRAPPER",
                function_name="init_c2",
                address="0x401200",
                line_number=5,
                code_snippet="int s = socket(2, 1, 0);",
                arguments="2, 1, 0",
            ),
        ]

        decompiled = {
            "spawn_shell": """void spawn_shell() {
    char *args[] = {"/bin/sh", NULL};
    execve("/bin/sh", args, NULL);
}""",
        }

        generator = MarkdownReportGenerator(
            metadata=metadata,
            findings=findings,
            decompiled_functions=decompiled,
        )

        md_output = generator.generate()

        # Check key sections
        self.assertIn("# 🛡️ System Call Analysis Report: `malicious_sample.elf`", md_output)
        self.assertIn("112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00", md_output)
        self.assertIn("Process & Execution", md_output)
        self.assertIn("Networking & Sockets", md_output)
        self.assertIn("`execve`", md_output)
        self.assertIn("`socket`", md_output)
        self.assertIn("Decompiled Evidence & Callsite Context", md_output)
        self.assertIn("View Full Decompiled Function", md_output)

        # Test writing to file
        with tempfile.TemporaryDirectory() as tmpdir:
            out_path = Path(tmpdir) / "report.md"
            written = generator.write_to_file(out_path)
            self.assertTrue(written.exists())
            self.assertGreater(written.stat().st_size, 100)


if __name__ == "__main__":
    unittest.main()
