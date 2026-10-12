"""End-to-End integration tests for CLI and analyzer pipeline."""

import tempfile
import unittest
from pathlib import Path

from ghidra_syscall_analyzer.cli import main


class TestEndToEnd(unittest.TestCase):

    def test_mock_dry_run_cli(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            sample_file = Path(tmpdir) / "target_applet.jar"
            sample_file.write_bytes(b"PK\x03\x04fake_jar_content")

            output_md = Path(tmpdir) / "output_report.md"

            ret = main([
                str(sample_file),
                "-o", str(output_md),
                "--mock-dry-run",
            ])

            self.assertEqual(ret, 0)
            self.assertTrue(output_md.exists())

            content = output_md.read_text(encoding="utf-8")
            self.assertIn("target_applet.jar", content)
            self.assertIn("System Call Analysis Report", content)
            self.assertIn("Analysis Dashboard", content)
            self.assertIn("System Calls Inventory", content)
            self.assertIn("execve", content)
            self.assertIn("mprotect", content)

    def test_cli_missing_target_fails(self) -> None:
        with self.assertRaises(SystemExit) as ctx:
            main([])
        self.assertNotEqual(ctx.exception.code, 0)


if __name__ == "__main__":
    unittest.main()
