"""Localhost web server for the Freida malware analysis web UI.

Serves a single-page UI where a user uploads a binary, picks analysis and
AI-report options, and reads the resulting reports. Each upload becomes a
job: the analyzer CLI (and optionally `freida-report`) runs in a subprocess
inside the job's own folder, one job at a time, so Ghidra's JVM never has to
be shared between runs.

Usage:
    freida-web [--host 127.0.0.1] [--port 8765] [--workdir freida_web_jobs]
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import logging
import os
import queue
import re
import shutil
import subprocess
import sys
import threading
import time
import uuid
import webbrowser
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, unquote, urlparse

from freida.report_agent import (
    DEFAULT_MAX_COST,
    DEFAULT_MAX_TOOL_CALLS,
    DEFAULT_MODEL,
    DEFAULT_THINKING,
    THINKING_LEVELS,
)

logger = logging.getLogger("freida.webui")

PACKAGE_DIR = Path(__file__).resolve().parent.parent
STATIC_DIR = Path(__file__).resolve().parent / "static"
SAMPLE_BINARY = PACKAGE_DIR / "samples" / "sample_binary"

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8765
DEFAULT_WORKDIR = Path("freida_web_jobs")
DEFAULT_MAX_UPLOAD_MB = 200

BACKEND_CHOICES = ("pyghidra", "mcp", "mock")
JOB_ID_RE = re.compile(r"^[0-9a-f]{32}$")
LOG_TAIL_CHARS = 200_000

STATIC_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
}
OUTPUT_TYPES = {
    ".md": "text/markdown; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".pdf": "application/pdf",
    ".txt": "text/plain; charset=utf-8",
}
CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "frame-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'self'"
)


class OptionError(ValueError):
    """An option from the UI is missing or out of range."""


def safe_filename(name: str) -> str:
    """Keeps the uploaded file's base name, limited to characters that are safe on any filesystem."""
    base = Path(name.replace("\\", "/")).name
    cleaned = re.sub(r"[^A-Za-z0-9._-]", "_", base).strip("._") or "binary"
    return cleaned[:100]


def _number(params: Dict[str, str], key: str, cast, low: float, high: float, default=None):
    raw = params.get(key, "").strip()
    if raw == "":
        return default
    try:
        value = cast(raw)
    except ValueError:
        raise OptionError(f"{key} must be a number") from None
    if not low <= value <= high:
        raise OptionError(f"{key} must be between {low} and {high}")
    return value


def _flag(params: Dict[str, str], key: str) -> bool:
    return params.get(key, "").lower() in ("1", "true", "on", "yes")


def parse_options(params: Dict[str, str]) -> Dict[str, Any]:
    """Validates the options sent by the UI; unknown keys are ignored."""
    backend = params.get("backend", "pyghidra")
    if backend not in BACKEND_CHOICES:
        raise OptionError(f"backend must be one of {', '.join(BACKEND_CHOICES)}")
    options: Dict[str, Any] = {
        "backend": backend,
        "ghidra_dir": params.get("ghidra_dir", "").strip(),
        "mcp_cmd": params.get("mcp_cmd", "").strip(),
        "server_url": params.get("server_url", "").strip(),
        "max_functions": _number(params, "max_functions", int, 1, 1_000_000),
        "decompile_timeout": _number(params, "decompile_timeout", int, 1, 3600, 60),
        "timeout": _number(params, "timeout", float, 1, 3600, 120.0),
        "pdf": not _flag(params, "no_pdf"),
        "verbose": _flag(params, "verbose"),
        "ai": _flag(params, "ai"),
        "ai_dry_run": _flag(params, "ai_dry_run"),
        "model": params.get("model", "").strip() or DEFAULT_MODEL,
        "max_tool_calls": _number(params, "max_tool_calls", int, 0, 20, DEFAULT_MAX_TOOL_CALLS),
        "thinking": params.get("thinking", DEFAULT_THINKING),
        "max_cost": _number(params, "max_cost", float, 0, 100, DEFAULT_MAX_COST),
    }
    if backend == "mcp" and not (options["mcp_cmd"] or options["server_url"]):
        raise OptionError("the mcp backend needs an MCP command or a server URL")
    if options["thinking"] not in THINKING_LEVELS:
        raise OptionError(f"thinking must be one of {', '.join(THINKING_LEVELS)}")
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,80}", options["model"]):
        raise OptionError("model name contains unexpected characters")
    return options


def analysis_command(options: Dict[str, Any], binary: Path, out_dir: Path, stem: str) -> List[str]:
    """Builds the analyzer CLI invocation for a job."""
    cmd = [
        sys.executable, "-m", "freida.cli", str(binary),
        "-o", str(out_dir / f"{stem}_syscalls.md"),
        "--context-out", str(out_dir / f"{stem}_context.json"),
        "--facts-out", str(out_dir / f"{stem}_facts.json"),
    ]
    if not options["pdf"]:
        cmd.append("--no-pdf")
    if options["verbose"]:
        cmd.append("--verbose")
    if options["backend"] == "mock":
        cmd.append("--mock-dry-run")
        return cmd
    cmd += ["--backend", options["backend"], "--timeout", str(options["timeout"]),
            "--decompile-timeout", str(options["decompile_timeout"])]
    if options["ghidra_dir"]:
        cmd += ["--ghidra-dir", options["ghidra_dir"]]
    if options["max_functions"]:
        cmd += ["--max-functions", str(options["max_functions"])]
    if options["backend"] == "mcp":
        if options["mcp_cmd"]:
            cmd += ["--mcp-cmd", options["mcp_cmd"]]
        if options["server_url"]:
            cmd += ["--server-url", options["server_url"]]
    return cmd


def report_command(options: Dict[str, Any], out_dir: Path, stem: str) -> List[str]:
    """Builds the `freida-report` invocation for a job."""
    cmd = [
        sys.executable, "-m", "freida.report_agent", str(out_dir / f"{stem}_context.json"),
        "--model", options["model"],
        "--max-tool-calls", str(options["max_tool_calls"]),
        "--thinking", options["thinking"],
        "--max-cost", str(options["max_cost"]),
    ]
    if not options["pdf"]:
        cmd.append("--no-pdf")
    if options["ai_dry_run"]:
        cmd.append("--dry-run")
    if options["verbose"]:
        cmd.append("--verbose")
    return cmd


class Job:
    """One uploaded binary and the runs made on it."""

    def __init__(self, root: Path, job_id: str, filename: str, options: Dict[str, Any]) -> None:
        self.id = job_id
        self.dir = root / job_id
        self.filename = filename
        self.options = options
        self.status = "queued"
        self.steps: List[Dict[str, Any]] = []
        self.created = time.time()
        self.finished: Optional[float] = None
        self.error = ""
        self.process: Optional[subprocess.Popen] = None
        self.cancelled = False
        self.lock = threading.Lock()

    @property
    def input_path(self) -> Path:
        return self.dir / "input" / self.filename

    @property
    def output_dir(self) -> Path:
        return self.dir / "output"

    @property
    def log_path(self) -> Path:
        return self.dir / "log.txt"

    @property
    def stem(self) -> str:
        return Path(self.filename).stem or "binary"

    def outputs(self) -> List[Dict[str, Any]]:
        if not self.output_dir.is_dir():
            return []
        files = []
        for path in sorted(self.output_dir.iterdir()):
            if path.is_file() and path.suffix in OUTPUT_TYPES:
                files.append({"name": path.name, "size": path.stat().st_size, "kind": self._kind(path.name)})
        return files

    def _kind(self, name: str) -> str:
        if name.endswith("_syscalls.md"):
            return "syscall_report"
        if name.endswith("_overview.md"):
            return "ai_report"
        return "file"

    def log_text(self) -> str:
        try:
            text = self.log_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return ""
        return text[-LOG_TAIL_CHARS:]

    def summary(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "filename": self.filename,
            "status": self.status,
            "created": self.created,
            "finished": self.finished,
            "error": self.error,
            "backend": self.options.get("backend"),
            "ai": self.options.get("ai", False),
        }

    def detail(self) -> Dict[str, Any]:
        data = self.summary()
        data.update({"options": self.options, "steps": self.steps, "outputs": self.outputs(), "log": self.log_text()})
        return data

    def save(self) -> None:
        record = self.summary()
        record.update({"options": self.options, "steps": self.steps})
        (self.dir / "job.json").write_text(json.dumps(record, indent=2), encoding="utf-8")

    @classmethod
    def load(cls, root: Path, path: Path) -> "Job":
        record = json.loads(path.read_text(encoding="utf-8"))
        job = cls(root, record["id"], record["filename"], record.get("options", {}))
        job.status = record.get("status", "failed")
        job.steps = record.get("steps", [])
        job.created = record.get("created", path.stat().st_mtime)
        job.finished = record.get("finished")
        job.error = record.get("error", "")
        if job.status in ("queued", "running"):
            job.status, job.error = "failed", "Interrupted: the server stopped before this job finished."
        return job


class JobManager:
    """Keeps jobs on disk and runs them one at a time on a worker thread."""

    def __init__(self, workdir: Path) -> None:
        self.workdir = workdir.resolve()
        self.workdir.mkdir(parents=True, exist_ok=True)
        self.jobs: Dict[str, Job] = {}
        self.secrets: Dict[str, str] = {}  # job id -> Gemini key for that run only; never written to disk
        self.queue: "queue.Queue[str]" = queue.Queue()
        self._load_existing()
        threading.Thread(target=self._worker, name="freida-web-worker", daemon=True).start()

    def _load_existing(self) -> None:
        for record in self.workdir.glob("*/job.json"):
            try:
                job = Job.load(self.workdir, record)
            except (OSError, ValueError, KeyError) as e:
                logger.warning("Skipping unreadable job %s: %s", record.parent.name, e)
                continue
            self.jobs[job.id] = job

    def list(self) -> List[Dict[str, Any]]:
        return [job.summary() for job in sorted(self.jobs.values(), key=lambda j: j.created, reverse=True)]

    def get(self, job_id: str) -> Optional[Job]:
        return self.jobs.get(job_id) if JOB_ID_RE.match(job_id) else None

    def create(self, filename: str, data: bytes, options: Dict[str, Any], gemini_key: str = "") -> Job:
        job = Job(self.workdir, uuid.uuid4().hex, safe_filename(filename), options)
        job.input_path.parent.mkdir(parents=True)
        job.output_dir.mkdir()
        job.input_path.write_bytes(data)
        job.save()
        self.jobs[job.id] = job
        if gemini_key:
            self.secrets[job.id] = gemini_key
        self.queue.put(job.id)
        return job

    def cancel(self, job: Job) -> None:
        with job.lock:
            job.cancelled = True
            if job.process and job.process.poll() is None:
                job.process.terminate()

    def delete(self, job: Job) -> None:
        self.cancel(job)
        self.jobs.pop(job.id, None)
        self.secrets.pop(job.id, None)
        shutil.rmtree(job.dir, ignore_errors=True)

    def _worker(self) -> None:
        while True:
            job_id = self.queue.get()
            job = self.jobs.get(job_id)
            if job is None:
                continue
            try:
                self._run(job)
            except Exception as e:  # keep the worker alive for the next job
                logger.exception("Job %s crashed", job.id)
                job.status, job.error = "failed", str(e)
            finally:
                self.secrets.pop(job.id, None)
                job.finished = time.time()
                if job.dir.exists():
                    job.save()

    def _run(self, job: Job) -> None:
        if job.cancelled:
            job.status, job.error = "cancelled", "Cancelled before it started."
            return
        job.status = "running"
        job.save()
        options = job.options

        ok = self._step(job, "Syscall analysis", analysis_command(options, job.input_path, job.output_dir, job.stem))
        if ok and options["ai"]:
            if options["backend"] == "mock":
                self._note(job, "AI report skipped: the mock backend writes no model context.")
            else:
                env = {}
                key = self.secrets.get(job.id)
                if key:
                    env["GEMINI_API_KEY"] = key
                ok = self._step(job, "AI behavioral overview", report_command(options, job.output_dir, job.stem), env)

        if job.cancelled:
            job.status, job.error = "cancelled", "Cancelled."
        elif ok:
            job.status = "done"
        else:
            job.status = "failed"
            failed = next((s for s in job.steps if s["returncode"] not in (0, None)), None)
            job.error = f"{failed['name']} exited with code {failed['returncode']}; see the log." if failed else "Failed."

    def _note(self, job: Job, message: str) -> None:
        with open(job.log_path, "a", encoding="utf-8") as log:
            log.write(f"[i] {message}\n")

    def _step(self, job: Job, name: str, cmd: List[str], extra_env: Optional[Dict[str, str]] = None) -> bool:
        step = {"name": name, "status": "running", "returncode": None, "started": time.time(), "finished": None}
        job.steps.append(step)
        job.save()
        env = os.environ.copy()
        env["PYTHONUNBUFFERED"] = "1"
        env["PYTHONPATH"] = os.pathsep.join(filter(None, [str(PACKAGE_DIR.parent), env.get("PYTHONPATH", "")]))
        env.update(extra_env or {})
        with open(job.log_path, "a", encoding="utf-8") as log:
            log.write(f"=== {name} ===\n$ {' '.join(_display_arg(a, job) for a in cmd)}\n")
            log.flush()
            with job.lock:
                if job.cancelled:
                    step.update(status="cancelled", finished=time.time())
                    return False
                job.process = subprocess.Popen(
                    cmd, cwd=job.dir, env=env, stdout=log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                )
            returncode = job.process.wait()
            log.write(f"=== {name} exited with code {returncode} ===\n\n")
        job.process = None
        step.update(returncode=returncode, finished=time.time(),
                    status="cancelled" if job.cancelled else ("done" if returncode == 0 else "failed"))
        job.save()
        return returncode == 0 and not job.cancelled


def _display_arg(arg: str, job: Job) -> str:
    """Shortens paths inside the job folder and the interpreter path for the log."""
    if arg == sys.executable:
        return "python"
    arg = arg.replace(str(job.dir) + os.sep, "")
    return f"'{arg}'" if " " in arg else arg


class FreidaHandler(BaseHTTPRequestHandler):
    server_version = "FreidaWeb/1.0"
    manager: JobManager
    max_upload: int
    allowed_hosts: set

    # --- plumbing -----------------------------------------------------------------

    def log_message(self, fmt: str, *args: Any) -> None:
        logger.debug("%s - %s", self.address_string(), fmt % args)

    def _host_ok(self) -> bool:
        """Rejects requests for other host names (DNS rebinding)."""
        host = (self.headers.get("Host") or "").strip().lower()
        if host.startswith("["):
            host = host[1:].split("]")[0]
        else:
            host = host.rsplit(":", 1)[0]
        return host in self.allowed_hosts

    def _send(self, status: int, body: bytes, content_type: str, extra: Optional[Dict[str, str]] = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, data: Any, status: int = 200) -> None:
        self._send(status, json.dumps(data).encode("utf-8"), "application/json; charset=utf-8")

    def _error(self, status: int, message: str) -> None:
        self._json({"error": message}, status)

    def _route(self) -> List[str]:
        return [unquote(part) for part in urlparse(self.path).path.split("/") if part]

    # --- GET ----------------------------------------------------------------------

    def do_GET(self) -> None:
        if not self._host_ok():
            return self._error(HTTPStatus.FORBIDDEN, "Unexpected Host header.")
        parts = self._route()
        if not parts or parts == ["index.html"]:
            return self._static("index.html")
        if parts[0] == "static" and len(parts) == 2:
            return self._static(parts[1])
        if parts[0] != "api":
            return self._error(HTTPStatus.NOT_FOUND, "Not found.")
        if parts[1:] == ["config"]:
            return self._json(self._config())
        if parts[1:] == ["jobs"]:
            return self._json({"jobs": self.manager.list()})
        if len(parts) >= 3 and parts[1] == "jobs":
            job = self.manager.get(parts[2])
            if job is None:
                return self._error(HTTPStatus.NOT_FOUND, "No such job.")
            if len(parts) == 3:
                return self._json(job.detail())
            if len(parts) == 5 and parts[3] == "files":
                return self._output(job, parts[4])
        return self._error(HTTPStatus.NOT_FOUND, "Not found.")

    do_HEAD = do_GET

    def _static(self, name: str) -> None:
        path = STATIC_DIR / name
        if name not in {p.name for p in STATIC_DIR.iterdir()} or path.suffix not in STATIC_TYPES:
            return self._error(HTTPStatus.NOT_FOUND, "Not found.")
        extra = {"Content-Security-Policy": CSP} if path.suffix == ".html" else None
        self._send(HTTPStatus.OK, path.read_bytes(), STATIC_TYPES[path.suffix], extra)

    def _output(self, job: Job, name: str) -> None:
        if name not in {f["name"] for f in job.outputs()}:
            return self._error(HTTPStatus.NOT_FOUND, "No such output file.")
        path = job.output_dir / name
        disposition = "attachment" if "download" in parse_qs(urlparse(self.path).query) else "inline"
        self._send(HTTPStatus.OK, path.read_bytes(), OUTPUT_TYPES[path.suffix], {
            "Content-Disposition": f'{disposition}; filename="{name}"',
            "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; sandbox",
        } if path.suffix != ".pdf" else {"Content-Disposition": f'{disposition}; filename="{name}"'})

    def _config(self) -> Dict[str, Any]:
        return {
            "ghidra_install_dir": os.environ.get("GHIDRA_INSTALL_DIR", ""),
            "pyghidra_installed": importlib.util.find_spec("pyghidra") is not None,
            "gemini_key_set": bool(os.environ.get("GEMINI_API_KEY")),
            "sample_available": SAMPLE_BINARY.is_file(),
            "max_upload_mb": self.max_upload // (1024 * 1024),
            "backends": list(BACKEND_CHOICES),
            "defaults": {
                "model": DEFAULT_MODEL,
                "max_tool_calls": DEFAULT_MAX_TOOL_CALLS,
                "thinking": DEFAULT_THINKING,
                "thinking_levels": list(THINKING_LEVELS),
                "max_cost": DEFAULT_MAX_COST,
                "decompile_timeout": 60,
                "timeout": 120,
            },
        }

    # --- POST / DELETE ------------------------------------------------------------

    def _api_guard(self) -> bool:
        """Host check plus a custom header, which a cross-site page cannot send without a CORS preflight."""
        if not self._host_ok():
            self._error(HTTPStatus.FORBIDDEN, "Unexpected Host header.")
            return False
        if self.headers.get("X-Freida") != "1":
            self._error(HTTPStatus.FORBIDDEN, "Missing X-Freida header.")
            return False
        return True

    def do_POST(self) -> None:
        if not self._api_guard():
            return
        parts = self._route()
        if parts == ["api", "jobs"]:
            return self._create_job()
        if len(parts) == 4 and parts[:2] == ["api", "jobs"] and parts[3] == "cancel":
            job = self.manager.get(parts[2])
            if job is None:
                return self._error(HTTPStatus.NOT_FOUND, "No such job.")
            self.manager.cancel(job)
            return self._json(job.summary())
        self._error(HTTPStatus.NOT_FOUND, "Not found.")

    def do_DELETE(self) -> None:
        if not self._api_guard():
            return
        parts = self._route()
        if len(parts) == 3 and parts[:2] == ["api", "jobs"]:
            job = self.manager.get(parts[2])
            if job is None:
                return self._error(HTTPStatus.NOT_FOUND, "No such job.")
            self.manager.delete(job)
            return self._json({"deleted": job.id})
        self._error(HTTPStatus.NOT_FOUND, "Not found.")

    def _create_job(self) -> None:
        """The file is the raw request body; options come in the query string, the Gemini key in a header."""
        params = {k: v[-1] for k, v in parse_qs(urlparse(self.path).query, keep_blank_values=True).items()}
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return self._error(HTTPStatus.BAD_REQUEST, "Bad Content-Length.")
        if length > self.max_upload:
            return self._error(HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                               f"File is larger than {self.max_upload // (1024 * 1024)} MB.")
        try:
            options = parse_options(params)
        except OptionError as e:
            return self._error(HTTPStatus.BAD_REQUEST, str(e))

        if _flag(params, "sample"):
            if not SAMPLE_BINARY.is_file():
                return self._error(HTTPStatus.NOT_FOUND, "The bundled sample binary is missing.")
            filename, data = SAMPLE_BINARY.name, SAMPLE_BINARY.read_bytes()
        else:
            if length <= 0:
                return self._error(HTTPStatus.BAD_REQUEST, "Choose a file to analyze.")
            filename, data = params.get("filename", "binary"), self.rfile.read(length)
            if len(data) != length:
                return self._error(HTTPStatus.BAD_REQUEST, "Upload was cut short.")
            if Path(filename).suffix.lower() in {".class", ".jar", ".war"}:
                return self._error(HTTPStatus.BAD_REQUEST,
                                   "Java class/JAR files are not supported; upload a native executable (ELF, PE, Mach-O).")

        key = (self.headers.get("X-Gemini-Key") or "").strip()
        if options["ai"] and options["backend"] != "mock" and not options["ai_dry_run"] and not key and not os.environ.get("GEMINI_API_KEY"):
            return self._error(HTTPStatus.BAD_REQUEST,
                               "The AI report needs a Gemini API key: enter one, or start the server with GEMINI_API_KEY set.")
        job = self.manager.create(filename, data, options, key)
        self._json(job.summary(), HTTPStatus.CREATED)


def make_server(host: str, port: int, workdir: Path, max_upload_mb: int = DEFAULT_MAX_UPLOAD_MB) -> ThreadingHTTPServer:
    manager = JobManager(workdir)
    allowed = {"localhost", "127.0.0.1", "::1", host.lower()}
    handler = type("BoundFreidaHandler", (FreidaHandler,), {
        "manager": manager,
        "max_upload": max_upload_mb * 1024 * 1024,
        "allowed_hosts": allowed,
    })
    server = ThreadingHTTPServer((host, port), handler)
    server.daemon_threads = True
    server.manager = manager  # type: ignore[attr-defined]
    return server


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="freida-web", description="Run the Freida malware analysis web UI on a local web server.")
    parser.add_argument("--host", default=DEFAULT_HOST,
                        help=f"Interface to listen on (default: {DEFAULT_HOST}; only this machine can connect).")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"Port (default: {DEFAULT_PORT}; 0 picks a free one).")
    parser.add_argument("--workdir", type=Path, default=DEFAULT_WORKDIR,
                        help=f"Folder for uploads and reports (default: ./{DEFAULT_WORKDIR}).")
    parser.add_argument("--max-upload-mb", type=int, default=DEFAULT_MAX_UPLOAD_MB,
                        help=f"Largest accepted upload in MB (default: {DEFAULT_MAX_UPLOAD_MB}).")
    parser.add_argument("--open", action="store_true", help="Open the UI in the default browser.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Log every request.")
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s", datefmt="%H:%M:%S")
    if args.host not in ("127.0.0.1", "localhost", "::1"):
        logger.warning("Listening on %s: anyone who can reach this address can upload and run analyses.", args.host)

    try:
        server = make_server(args.host, args.port, args.workdir, args.max_upload_mb)
    except OSError as e:
        print(f"[!] Could not listen on {args.host}:{args.port}: {e}")
        return 1
    host, port = server.server_address[:2]
    url = f"http://{'localhost' if host in ('127.0.0.1', '::1') else host}:{port}/"
    print(f"[+] Freida web UI running at {url}")
    print(f"[i] Jobs are stored in {server.manager.workdir}")  # type: ignore[attr-defined]
    print("[i] Press Ctrl+C to stop.")
    if args.open:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[i] Stopping.")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
