"""End-to-End integration tests for CLI and analyzer pipeline."""

import tempfile
import unittest
from pathlib import Path

from ghidra_syscall_analyzer.cli import main


class TestEndToEnd(unittest.TestCase):

    def test_mock_dry_run_cli(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            sample_file = Path(tmpdir) / "target_binary"
            sample_file.write_bytes(b"\x7fELF\x02fake_elf_content")

            output_md = Path(tmpdir) / "output_report.md"

            ret = main([
                str(sample_file),
                "-o", str(output_md),
                "--mock-dry-run",
            ])

            self.assertEqual(ret, 0)
            self.assertTrue(output_md.exists())

            content = output_md.read_text(encoding="utf-8")
            self.assertIn("target_binary", content)
            self.assertIn("System Call Analysis Report", content)
            self.assertIn("Analysis Dashboard", content)
            self.assertIn("System Calls Inventory", content)
            self.assertIn("execve", content)
            self.assertIn("mprotect", content)

            pdf = output_md.with_suffix(".pdf")
            self.assertTrue(pdf.read_bytes().startswith(b"%PDF"))

    def test_pdf_out_and_no_pdf(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            sample_file = Path(tmpdir) / "target_binary"
            sample_file.write_bytes(b"\x7fELF\x02fake_elf_content")
            output_md = Path(tmpdir) / "report.md"
            custom_pdf = Path(tmpdir) / "pdfs" / "custom.pdf"

            self.assertEqual(main([str(sample_file), "-o", str(output_md), "--pdf-out", str(custom_pdf),
                                   "--mock-dry-run"]), 0)
            self.assertTrue(custom_pdf.exists())
            self.assertFalse(output_md.with_suffix(".pdf").exists())

            other_md = Path(tmpdir) / "other.md"
            self.assertEqual(main([str(sample_file), "-o", str(other_md), "--no-pdf", "--mock-dry-run"]), 0)
            self.assertTrue(other_md.exists())
            self.assertFalse(other_md.with_suffix(".pdf").exists())

    def test_cli_missing_target_fails(self) -> None:
        with self.assertRaises(SystemExit) as ctx:
            main([])
        self.assertNotEqual(ctx.exception.code, 0)


if __name__ == "__main__":
    unittest.main()
