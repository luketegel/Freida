"""Tests for the local web UI server."""

import json
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from freida.webui.server import (
    OptionError,
    analysis_command,
    make_server,
    parse_options,
    report_command,
    safe_filename,
)

SAMPLE = Path(__file__).resolve().parent.parent / "freida" / "samples" / "sample_binary"


class TestOptions(unittest.TestCase):

    def test_safe_filename(self) -> None:
        self.assertEqual(safe_filename("../../etc/passwd"), "passwd")
        self.assertEqual(safe_filename("C:\\Users\\me\\evil bin.exe"), "evil_bin.exe")
        self.assertEqual(safe_filename("..."), "binary")

    def test_defaults_and_validation(self) -> None:
        options = parse_options({})
        self.assertEqual(options["backend"], "pyghidra")
        self.assertTrue(options["pdf"])
        self.assertFalse(options["ai"])
        with self.assertRaises(OptionError):
            parse_options({"backend": "shell"})
        with self.assertRaises(OptionError):
            parse_options({"backend": "mcp"})
        with self.assertRaises(OptionError):
            parse_options({"decompile_timeout": "abc"})
        with self.assertRaises(OptionError):
            parse_options({"max_tool_calls": "500"})
        with self.assertRaises(OptionError):
            parse_options({"model": "x; rm -rf /"})

    def test_commands(self) -> None:
        options = parse_options({"backend": "mcp", "server_url": "http://127.0.0.1:8081", "max_functions": "50",
                                 "no_pdf": "1", "ai": "1", "ai_dry_run": "1", "max_tool_calls": "0"})
        cmd = analysis_command(options, Path("/j/input/a.out"), Path("/j/output"), "a")
        self.assertIn("--server-url", cmd)
        self.assertIn("--no-pdf", cmd)
        self.assertEqual(cmd[cmd.index("--max-functions") + 1], "50")
        self.assertEqual(cmd[cmd.index("--context-out") + 1], str(Path("/j/output/a_context.json")))
        report = report_command(options, Path("/j/output"), "a")
        self.assertIn("--dry-run", report)
        self.assertEqual(report[report.index("--max-tool-calls") + 1], "0")

        mock = analysis_command(parse_options({"backend": "mock"}), Path("/j/input/a"), Path("/j/output"), "a")
        self.assertIn("--mock-dry-run", mock)
        self.assertNotIn("--backend", mock)


class TestServer(unittest.TestCase):

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.server = make_server("127.0.0.1", 0, Path(self.tmp.name))
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.tmp.cleanup()

    def request(self, path, method="GET", data=None, headers=None):
        req = urllib.request.Request(self.base + path, data=data, method=method, headers=headers or {})
        try:
            with urllib.request.urlopen(req, timeout=10) as res:
                return res.status, res.headers, res.read()
        except urllib.error.HTTPError as e:
            return e.code, e.headers, e.read()

    def wait_for(self, job_id, timeout=60):
        deadline = time.time() + timeout
        while time.time() < deadline:
            _, _, body = self.request(f"/api/jobs/{job_id}")
            job = json.loads(body)
            if job["status"] not in ("queued", "running"):
                return job
            time.sleep(0.2)
        self.fail("job did not finish")

    def test_index_and_config(self) -> None:
        status, headers, body = self.request("/")
        self.assertEqual(status, 200)
        self.assertIn(b"Freida", body)
        self.assertIn("default-src 'self'", headers["Content-Security-Policy"])
        status, _, body = self.request("/api/config")
        self.assertEqual(status, 200)
        self.assertIn("pyghidra", json.loads(body)["backends"])
        self.assertEqual(self.request("/static/../server.py")[0], 404)

    def test_post_requires_header_and_local_host(self) -> None:
        self.assertEqual(self.request("/api/jobs?backend=mock", "POST", b"x")[0], 403)
        self.assertEqual(self.request("/api/jobs", headers={"Host": "attacker.example"})[0], 403)

    def test_rejects_bad_options_and_java(self) -> None:
        headers = {"X-Freida": "1"}
        self.assertEqual(self.request("/api/jobs?backend=nope", "POST", b"x", headers)[0], 400)
        self.assertEqual(self.request("/api/jobs?backend=mock&filename=a.jar", "POST", b"x", headers)[0], 400)
        self.assertEqual(self.request("/api/jobs?backend=mock", "POST", b"", headers)[0], 400)

    @unittest.skipUnless(SAMPLE.exists(), "bundled sample missing")
    def test_mock_job_end_to_end(self) -> None:
        status, _, body = self.request("/api/jobs?backend=mock&filename=../my%20prog", "POST",
                                       SAMPLE.read_bytes(), {"X-Freida": "1"})
        self.assertEqual(status, 201, body)
        job = self.wait_for(json.loads(body)["id"])
        self.assertEqual(job["status"], "done", job["log"])
        self.assertEqual(job["filename"], "my_prog")
        names = {f["name"] for f in job["outputs"]}
        self.assertIn("my_prog_syscalls.md", names)

        status, headers, report = self.request(f"/api/jobs/{job['id']}/files/my_prog_syscalls.md")
        self.assertEqual(status, 200)
        self.assertIn(b"System Call Analysis Report", report)
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(self.request(f"/api/jobs/{job['id']}/files/..%2Fjob.json")[0], 404)

        _, _, listing = self.request("/api/jobs")
        self.assertEqual(json.loads(listing)["jobs"][0]["id"], job["id"])

        self.assertEqual(self.request(f"/api/jobs/{job['id']}", "DELETE", headers={"X-Freida": "1"})[0], 200)
        self.assertEqual(self.request(f"/api/jobs/{job['id']}")[0], 404)

    def test_ai_report_needs_key(self) -> None:
        import os
        if os.environ.get("GEMINI_API_KEY"):
            self.skipTest("GEMINI_API_KEY is set")
        status, _, body = self.request("/api/jobs?backend=pyghidra&ai=1&filename=a", "POST", b"x", {"X-Freida": "1"})
        self.assertEqual(status, 400)
        self.assertIn(b"Gemini API key", body)


if __name__ == "__main__":
    unittest.main()
