"""PDF Report Generator for Ghidra Syscall Analyzer.

Renders the same results as the Markdown reports (the syscall analysis
report and the Behavioral Overview) as clean, printable PDF documents.
The PDFs are built from the structured data, not converted from Markdown,
so tables, severity colors and code blocks lay out properly on the page.
"""

from __future__ import annotations

import collections
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    CondPageBreak,
    KeepTogether,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)
from reportlab.platypus.flowables import Flowable, HRFlowable

from ghidra_syscall_analyzer.report_generator import BACKEND_LABELS
from ghidra_syscall_analyzer.syscall_detector import SyscallFinding

PAGE_SIZE = A4
MARGIN = 18 * mm
CONTENT_WIDTH = PAGE_SIZE[0] - 2 * MARGIN
CODE_PREVIEW_LINES = 40
CODE_WRAP_COLUMNS = 96

INK = colors.HexColor("#1f2937")
MUTED = colors.HexColor("#6b7280")
ACCENT = colors.HexColor("#1e3a5f")
RULE = colors.HexColor("#d1d5db")
HEADER_BG = colors.HexColor("#eef2f7")
ZEBRA_BG = colors.HexColor("#f8fafc")
CODE_BG = colors.HexColor("#f3f4f6")
WARN = colors.HexColor("#b45309")

SEVERITY_COLORS = {
    "CRITICAL": colors.HexColor("#b91c1c"),
    "HIGH": colors.HexColor("#c2410c"),
    "MEDIUM": colors.HexColor("#a16207"),
    "LOW": colors.HexColor("#15803d"),
    "INFO": colors.HexColor("#6b7280"),
}

CLASSIFICATION_COLORS = {
    "benign": colors.HexColor("#15803d"),
    "potentially_unwanted": colors.HexColor("#a16207"),
    "suspicious": colors.HexColor("#c2410c"),
    "malicious": colors.HexColor("#b91c1c"),
    "unknown": colors.HexColor("#6b7280"),
}

def _styles() -> Dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    body = ParagraphStyle("Body", parent=base["BodyText"], fontName="Helvetica", fontSize=9.5,
                          leading=13, textColor=INK, spaceAfter=4)
    return {
        "title": ParagraphStyle("Title", parent=body, fontName="Helvetica-Bold", fontSize=20, leading=24,
                                textColor=ACCENT, spaceAfter=4),
        "subtitle": ParagraphStyle("Subtitle", parent=body, fontSize=9, leading=12, textColor=MUTED),
        "h1": ParagraphStyle("H1", parent=body, fontName="Helvetica-Bold", fontSize=13.5, leading=17,
                             textColor=ACCENT, spaceBefore=12, spaceAfter=6),
        "h2": ParagraphStyle("H2", parent=body, fontName="Helvetica-Bold", fontSize=11, leading=14,
                             textColor=INK, spaceBefore=8, spaceAfter=4),
        "body": body,
        "bullet": ParagraphStyle("Bullet", parent=body, leftIndent=10, bulletIndent=0),
        "cell": ParagraphStyle("Cell", parent=body, fontSize=8, leading=10, spaceAfter=0),
        "cell_bold": ParagraphStyle("CellBold", parent=body, fontName="Helvetica-Bold", fontSize=8,
                                    leading=10, spaceAfter=0),
        "cell_center": ParagraphStyle("CellCenter", parent=body, fontSize=8, leading=10, spaceAfter=0,
                                      alignment=TA_CENTER),
        "code": ParagraphStyle("Code", parent=body, fontName="Courier", fontSize=7.5, leading=9.2,
                               spaceAfter=0),
        "caption": ParagraphStyle("Caption", parent=body, fontSize=8, leading=10, textColor=MUTED),
    }


STYLES = _styles()


def text(value: Any) -> str:
    """Escapes arbitrary text (binary strings, decompiled code) for a Paragraph."""
    return escape(str(value if value is not None else ""))


def mono(value: Any) -> str:
    return f'<font face="Courier">{text(value)}</font>'


def severity_label(severity: str) -> str:
    color = SEVERITY_COLORS.get(severity.upper(), MUTED)
    return f'<font color="{color.hexval()}"><b>{text(severity.upper())}</b></font>'


class CategoryBar(Flowable):
    """A horizontal proportion bar for the category distribution table."""

    def __init__(self, fraction: float, width: float = 60 * mm, height: float = 3.2 * mm) -> None:
        super().__init__()
        self.fraction = max(0.0, min(1.0, fraction))
        self.width = width
        self.height = height

    def wrap(self, avail_width: float, avail_height: float):
        return self.width, self.height

    def draw(self) -> None:
        self.canv.setFillColor(HEADER_BG)
        self.canv.roundRect(0, 0, self.width, self.height, 1.5, stroke=0, fill=1)
        if self.fraction > 0:
            self.canv.setFillColor(ACCENT)
            self.canv.roundRect(0, 0, self.width * self.fraction, self.height, 1.5, stroke=0, fill=1)


def data_table(rows: List[List[Any]], col_widths: List[float], header: bool = True,
               align_center: Optional[List[int]] = None) -> Table:
    """A ruled table with a tinted header row and zebra striping that splits across pages."""
    table = Table(rows, colWidths=col_widths, repeatRows=1 if header else 0)
    commands = [
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 3.5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3.5),
        ("LINEBELOW", (0, 0), (-1, -1), 0.4, RULE),
        ("BOX", (0, 0), (-1, -1), 0.6, RULE),
    ]
    first = 0
    if header:
        commands += [("BACKGROUND", (0, 0), (-1, 0), HEADER_BG), ("LINEBELOW", (0, 0), (-1, 0), 0.8, ACCENT)]
        first = 1
    for row in range(first, len(rows)):
        if (row - first) % 2 == 1:
            commands.append(("BACKGROUND", (0, row), (-1, row), ZEBRA_BG))
    for column in align_center or []:
        commands.append(("ALIGN", (column, 0), (column, -1), "CENTER"))
    table.setStyle(TableStyle(commands))
    return table


def key_value_table(pairs: List[tuple]) -> Table:
    rows = [[Paragraph(text(key), STYLES["cell_bold"]), Paragraph(value, STYLES["cell"])] for key, value in pairs]
    return data_table(rows, [45 * mm, CONTENT_WIDTH - 45 * mm], header=False)


def _wrap_code_line(line: str) -> List[str]:
    line = line.expandtabs(4)
    if len(line) <= CODE_WRAP_COLUMNS:
        return [line]
    indent = len(line) - len(line.lstrip(" "))
    pieces = [line[:CODE_WRAP_COLUMNS]]
    rest = line[CODE_WRAP_COLUMNS:]
    continuation = " " * min(indent + 4, 40)
    width = CODE_WRAP_COLUMNS - len(continuation)
    while rest:
        pieces.append(continuation + rest[:width])
        rest = rest[width:]
    return pieces


def code_block(code: str, max_lines: Optional[int] = None) -> Table:
    """Monospaced code on a tinted background; one row per line so long listings split across pages."""
    lines = code.rstrip("\n").splitlines() or [""]
    omitted = 0
    if max_lines is not None and len(lines) > max_lines:
        omitted = len(lines) - max_lines
        lines = lines[:max_lines]
    wrapped = [piece for line in lines for piece in _wrap_code_line(line)]
    if omitted:
        wrapped.append(f"// ... [{omitted} lines truncated] ...")
    rows = [[Paragraph(text(line).replace(" ", "&nbsp;") or "&nbsp;", STYLES["code"])] for line in wrapped]
    table = Table(rows, colWidths=[CONTENT_WIDTH])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), CODE_BG),
        ("LINEBEFORE", (0, 0), (0, -1), 2, ACCENT),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
        ("TOPPADDING", (0, 0), (-1, 0), 4),
        ("BOTTOMPADDING", (0, -1), (-1, -1), 4),
    ]))
    return table


def _build(path: Union[str, Path], title: str, footer_label: str, story: List[Any]) -> Path:
    out_file = Path(path).resolve()
    out_file.parent.mkdir(parents=True, exist_ok=True)

    def decorate(canvas, doc) -> None:
        canvas.saveState()
        canvas.setStrokeColor(RULE)
        canvas.setLineWidth(0.5)
        canvas.line(MARGIN, MARGIN - 6 * mm, PAGE_SIZE[0] - MARGIN, MARGIN - 6 * mm)
        canvas.setFont("Helvetica", 7.5)
        canvas.setFillColor(MUTED)
        canvas.drawString(MARGIN, MARGIN - 10 * mm, footer_label)
        canvas.drawRightString(PAGE_SIZE[0] - MARGIN, MARGIN - 10 * mm, f"Page {doc.page}")
        canvas.restoreState()

    doc = SimpleDocTemplate(
        str(out_file), pagesize=PAGE_SIZE, leftMargin=MARGIN, rightMargin=MARGIN,
        topMargin=MARGIN, bottomMargin=MARGIN, title=title, author="Freida (Ghidra Syscall Analyzer)",
    )
    doc.build(story, onFirstPage=decorate, onLaterPages=decorate)
    return out_file


class PdfReportGenerator:
    """Renders the syscall analysis report (the Markdown report's content) as a PDF."""

    def __init__(
        self,
        metadata: Dict[str, Any],
        findings: List[SyscallFinding],
        decompiled_functions: Optional[Dict[str, str]] = None,
    ) -> None:
        self.metadata = metadata
        self.findings = findings
        self.decompiled_functions = decompiled_functions or {}

    def write_to_file(self, output_path: Union[str, Path]) -> Path:
        name = self.metadata.get("file_name", "Target Binary")
        return _build(output_path, f"System Call Analysis Report: {name}",
                      f"Freida · System Call Analysis Report · {name}", self.build_story())

    def build_story(self) -> List[Any]:
        story: List[Any] = []
        story += self._header()
        story += self._target_overview()
        story += self._dashboard()
        story += self._categories()
        story += self._observations()
        story += self._inventory()
        story += self._evidence()
        story += self._methodology()
        return story

    def _header(self) -> List[Any]:
        name = self.metadata.get("file_name", "Target Binary")
        backend = self.metadata.get("backend", "mcp")
        return [
            Paragraph(f"System Call Analysis Report: {mono(name)}", STYLES["title"]),
            Paragraph(
                f"Automated headless binary decompilation via Ghidra · Analysis date: "
                f"{text(self.metadata.get('analysis_time', 'N/A'))} · Mode: {text(BACKEND_LABELS.get(backend, backend))}",
                STYLES["subtitle"],
            ),
            Spacer(1, 6),
        ]

    def _target_overview(self) -> List[Any]:
        m = self.metadata
        size = f"{text(m.get('file_size_formatted', 'Unknown'))} ({m.get('file_size_bytes', 0):,} bytes)"
        pairs = [
            ("File Name", mono(m.get("file_name", "Unknown"))),
            ("Absolute Path", mono(m.get("absolute_path", "Unknown"))),
            ("File Format", text(m.get("file_type", "Unknown"))),
            ("Architecture", mono(m.get("architecture", m.get("format", "Auto-detected")))),
            ("File Size", size),
            ("SHA-256", mono(m.get("sha256", "N/A"))),
            ("MD-5", mono(m.get("md5", "N/A"))),
            ("Ghidra Program Name", mono(m.get("ghidra_program_name", m.get("file_name")))),
        ]
        return [Paragraph("Target Binary Information", STYLES["h1"]), key_value_table(pairs)]

    def _dashboard(self) -> List[Any]:
        severities = collections.Counter(f.severity for f in self.findings)
        funcs = self.metadata.get("functions_decompiled", len(self.decompiled_functions))
        metrics = [
            ("Functions decompiled", funcs, "Analyzed via Ghidra Decompiler"),
            ("Syscall invocations", len(self.findings), "Detected across all functions & imports"),
            ("Unique system calls", len({f.name for f in self.findings}), "Distinct system call primitives"),
            ("Critical severity", severities.get("CRITICAL", 0), "Injection, exec, arbitrary memory"),
            ("High severity", severities.get("HIGH", 0), "Process spawns, page protection, privileges"),
            ("Medium severity", severities.get("MEDIUM", 0), "Network sockets, file creation/deletion, IPC"),
            ("Low / info severity", severities.get("LOW", 0) + severities.get("INFO", 0),
             "File reads, clocks, system telemetry"),
        ]
        rows = [[Paragraph("<b>Metric</b>", STYLES["cell"]), Paragraph("<b>Count</b>", STYLES["cell_center"]),
                 Paragraph("<b>Details</b>", STYLES["cell"])]]
        for label, count, detail in metrics:
            sev = label.split()[0].upper()
            count_text = f"<b>{count}</b>"
            if sev in SEVERITY_COLORS and count:
                count_text = f'<font color="{SEVERITY_COLORS[sev].hexval()}"><b>{count}</b></font>'
            rows.append([Paragraph(text(label), STYLES["cell_bold"]), Paragraph(count_text, STYLES["cell_center"]),
                         Paragraph(text(detail), STYLES["cell"])])
        return [Paragraph("Analysis Dashboard", STYLES["h1"]),
                data_table(rows, [50 * mm, 20 * mm, CONTENT_WIDTH - 70 * mm])]

    def _categories(self) -> List[Any]:
        heading = Paragraph("System Call Categories", STYLES["h1"])
        categories = collections.Counter(f.category for f in self.findings)
        if not categories:
            return [heading, Paragraph("<i>No system calls detected.</i>", STYLES["body"])]
        top = max(categories.values())
        rows = [[Paragraph("<b>Category</b>", STYLES["cell"]), Paragraph("<b>Count</b>", STYLES["cell_center"]),
                 Paragraph("<b>Distribution</b>", STYLES["cell"])]]
        for category, count in categories.most_common():
            rows.append([Paragraph(text(category), STYLES["cell_bold"]), Paragraph(str(count), STYLES["cell_center"]),
                         CategoryBar(count / top)])
        return [heading, data_table(rows, [55 * mm, 20 * mm, CONTENT_WIDTH - 75 * mm])]

    def _observations(self) -> List[Any]:
        groups = [
            ("Direct Syscall", "Direct Kernel Entry", "Raw syscall instructions that bypass libc wrappers in",
             lambda f: f.function_name),
            ("Process & Execution", "Process Execution Capabilities",
             "Routines capable of spawning or altering processes", lambda f: f.name),
            ("Memory Management", "Dynamic Memory & Page Protection",
             "Target manages memory allocations and page permissions", lambda f: f.name),
            ("Networking & Sockets", "Network Communication",
             "Target initializes network sockets or connections", lambda f: f.name),
            ("File I/O", "Filesystem Operations", "Target accesses, modifies, or inspects files", lambda f: f.name),
            ("Security & Privileges", "Privilege / Capability Management",
             "Target interacts with system credentials or isolation controls", lambda f: f.name),
        ]
        items = []
        for category, title, sentence, key in groups:
            names = sorted({key(f) for f in self.findings if f.category == category})
            if names:
                items.append(Paragraph(f"<b>{text(title)}:</b> {text(sentence)}: {mono(', '.join(names))}.",
                                       STYLES["bullet"], bulletText="•"))
        if not items:
            items.append(Paragraph("<b>Low Risk:</b> No high-risk privileged system calls detected.",
                                   STYLES["bullet"], bulletText="•"))
        return [Paragraph("Security &amp; Behavioral Observations", STYLES["h1"]), *items]

    def _inventory(self) -> List[Any]:
        heading = Paragraph("System Calls Inventory", STYLES["h1"])
        if not self.findings:
            return [heading, Paragraph("<i>No system calls detected.</i>", STYLES["body"])]
        header = ["Syscall / API", "Category", "Severity", "Function / Address", "Line", "Type", "Arguments / Context"]
        rows: List[List[Any]] = [[Paragraph(f"<b>{h}</b>", STYLES["cell"]) for h in header]]
        for f in self.findings:
            location = mono(f.function_name)
            if f.callsite_address:
                location += f"<br/>call @ {mono(f.callsite_address)}"
            elif f.address:
                location += f"<br/>{mono(f.address)}"
            args = f.arguments if len(f.arguments) <= 60 else f"{f.arguments[:60]}..."
            rows.append([
                Paragraph(f"<b>{mono(f.name)}</b>", STYLES["cell"]),
                Paragraph(text(f.category), STYLES["cell"]),
                Paragraph(severity_label(f.severity), STYLES["cell_center"]),
                Paragraph(location, STYLES["cell"]),
                Paragraph(str(f.line_number or "—"), STYLES["cell_center"]),
                Paragraph(text(f.detection_type.replace("_", " ").title()), STYLES["cell"]),
                Paragraph(mono(args) if args else "—", STYLES["cell"]),
            ])
        widths = [26 * mm, 22 * mm, 17 * mm, 38 * mm, 9 * mm, 21 * mm]
        widths.append(CONTENT_WIDTH - sum(widths))
        return [CondPageBreak(50 * mm), heading, data_table(rows, widths)]

    def _evidence(self) -> List[Any]:
        by_func: Dict[str, List[SyscallFinding]] = collections.defaultdict(list)
        for f in self.findings:
            if f.function_name != "[IMPORT_TABLE]":
                by_func[f.function_name].append(f)
        if not by_func:
            return []

        story: List[Any] = [CondPageBreak(60 * mm), Paragraph("Decompiled Evidence &amp; Callsite Context", STYLES["h1"])]
        for func_name, func_findings in by_func.items():
            names = ", ".join(mono(f.name) for f in func_findings)
            story.append(KeepTogether([
                Paragraph(f"Function: {mono(func_name)}", STYLES["h2"]),
                Paragraph(f"<b>Detected system calls:</b> {names}", STYLES["body"]),
            ]))
            for f in func_findings:
                story.append(KeepTogether([
                    Paragraph(f"Line {f.line_number} · {mono(f.name)} · {text(f.category)}", STYLES["caption"]),
                    code_block(f.code_snippet),
                    Spacer(1, 4),
                ]))
            body = self.decompiled_functions.get(func_name)
            if body:
                story.append(Paragraph(f"Full decompiled function: {mono(func_name)}", STYLES["caption"]))
                story.append(code_block(body, max_lines=CODE_PREVIEW_LINES))
                story.append(Spacer(1, 6))
        return story

    def _methodology(self) -> List[Any]:
        backend = self.metadata.get("backend", "mcp")
        if backend == "pyghidra":
            engines = ["<b>Decompilation Engine:</b> Ghidra Decompiler (DecompInterface) driven in-process via PyGhidra."]
        elif backend == "mock":
            engines = ["<b>Decompilation Engine:</b> None. Mock dry run with built-in sample code; "
                       "the target was not decompiled."]
        else:
            engines = ["<b>Decompilation Engine:</b> Ghidra Decompiler via a Ghidra MCP server.",
                       "<b>Protocol:</b> Model Context Protocol (MCP) JSON-RPC 2.0 stdio / HTTP bridge."]
        bullets = engines + [
            "<b>Headless Execution:</b> Fully automated headless analysis without the Ghidra graphical user interface.",
            "<b>Detection Scope:</b> Direct syscall instructions (syscall, sysenter, int 0x80, svc #0), POSIX / libc "
            "wrappers, Windows Native NT and Win32 APIs, and macOS Mach traps in native executables "
            "(ELF, PE, Mach-O).",
        ]
        return [
            Paragraph("Methodology &amp; Tooling", STYLES["h1"]),
            Paragraph("This report was generated using <b>Ghidra Syscall Analyzer</b> in full <b>Headless Mode</b>:",
                      STYLES["body"]),
            *[Paragraph(b, STYLES["bullet"], bulletText="•") for b in bullets],
        ]


def _paragraphs(value: Any, style: ParagraphStyle) -> List[Paragraph]:
    """Model prose may contain blank-line separated paragraphs."""
    blocks = [block.strip() for block in str(value or "").split("\n\n") if block.strip()]
    return [Paragraph(text(block).replace("\n", "<br/>"), style) for block in blocks]


def write_overview_pdf(result: Dict[str, Any], target: Dict[str, Any], output_path: Union[str, Path]) -> Path:
    """Renders the Behavioral Overview (the `binary_overview.json` result) as a PDF.

    `result` is the agent result as written to the overview JSON; `target` is the
    context's `target` section.
    """
    name = target.get("file_name", "binary")
    story: List[Any] = [Paragraph(f"Analysis Report: {mono(name)}", STYLES["title"])]
    details = []
    if target.get("sha256"):
        details.append(f"SHA-256: {mono(target['sha256'])}")
    if target.get("architecture"):
        details.append(f"Architecture: {mono(target['architecture'])}")
    if details:
        story.append(Paragraph(" · ".join(details), STYLES["subtitle"]))
    story += [Spacer(1, 6), Paragraph("Behavioral Overview", STYLES["h1"])]

    overview = result.get("overview")
    if overview is None:
        story.append(Paragraph(
            f'<font color="{WARN.hexval()}"><b>The model did not return a valid structured overview</b></font> '
            f"(finish reason: {text(result.get('finish_reason'))}). Raw response:", STYLES["body"]))
        story.append(code_block((result.get("raw_text") or "").strip() or "(empty)"))
    else:
        story += _overview_body(overview)

    story += _usage_footer(result)
    return _build(output_path, f"Analysis Report: {name}", f"Freida · Behavioral Overview · {name}", story)


def _overview_body(overview: Dict[str, Any]) -> List[Any]:
    assessment = overview.get("assessment") or {}
    classification = str(assessment.get("classification", "unknown"))
    color = CLASSIFICATION_COLORS.get(classification, MUTED)
    verdict = Table(
        [[Paragraph(
            f'<font color="{color.hexval()}"><b>{text(classification.replace("_", " ").title())}</b></font>'
            f"&nbsp;&nbsp;<font color=\"{MUTED.hexval()}\">confidence: {text(assessment.get('confidence', 'unknown'))}"
            f"</font>", STYLES["h2"])],
         [Paragraph(text(assessment.get("rationale", "")), STYLES["body"])]],
        colWidths=[CONTENT_WIDTH],
    )
    verdict.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), HEADER_BG),
        ("LINEBEFORE", (0, 0), (0, -1), 3, color),
        ("LEFTPADDING", (0, 0), (-1, -1), 9),
        ("RIGHTPADDING", (0, 0), (-1, -1), 9),
        ("TOPPADDING", (0, 0), (-1, 0), 2),
        ("BOTTOMPADDING", (0, -1), (-1, -1), 6),
    ]))

    story: List[Any] = [Paragraph("<b>Assessment</b>", STYLES["caption"]), verdict, Spacer(1, 8)]
    story += _paragraphs(overview.get("summary"), STYLES["body"])
    story.append(Paragraph("Execution Flow", STYLES["h1"]))
    story += _paragraphs(overview.get("execution_flow"), STYLES["body"])

    story.append(Paragraph("Observed Behaviors", STYLES["h1"]))
    behaviors = overview.get("behaviors") or []
    if not behaviors:
        story.append(Paragraph("<i>No behaviors reported.</i>", STYLES["body"]))
    for number, behavior in enumerate(behaviors, start=1):
        severity = str(behavior.get("severity", "info"))
        block: List[Any] = [
            Paragraph(f"{number}. {text(behavior.get('title', 'Behavior'))}", STYLES["h2"]),
            Paragraph(f"{severity_label(severity)} &nbsp;·&nbsp; {mono(behavior.get('category', 'other'))}",
                      STYLES["body"]),
        ]
        block += _paragraphs(behavior.get("description"), STYLES["body"])
        story.append(KeepTogether(block))
        for evidence in behavior.get("evidence") or []:
            location = mono(evidence.get("function", "?"))
            if evidence.get("address"):
                location += f" @ {mono(evidence['address'])}"
            flag = ""
            if not evidence.get("verified", True):
                flag = f' <font color="{WARN.hexval()}"><i>(unverified: not found in the analysis facts)</i></font>'
            story.append(Paragraph(f"{location}: {text(evidence.get('detail', ''))}{flag}",
                                   STYLES["bullet"], bulletText="•"))

    if overview.get("limitations"):
        story.append(Paragraph("Limitations", STYLES["h1"]))
        story += [Paragraph(text(item), STYLES["bullet"], bulletText="•") for item in overview["limitations"]]
    return story


def _usage_footer(result: Dict[str, Any]) -> List[Any]:
    totals = (result.get("usage") or {}).get("total")
    if not totals:
        return []
    line = (
        f"Generated by {mono(result.get('model', 'unknown'))} · {totals.get('requests', 0)} request(s), "
        f"{totals.get('tool_calls', 0)} tool call(s) · {totals.get('input_tokens', 0):,} input "
        f"({totals.get('cached_tokens', 0):,} cached) / {totals.get('output_tokens', 0):,} output tokens · "
        f"<b>cost ${totals.get('cost_usd', 0.0):.4f}</b>"
    )
    estimate = result.get("estimate")
    if estimate:
        line += f" (estimate was ${estimate['min_cost_usd']:.4f} to ${estimate['max_cost_usd']:.4f})"
    return [Spacer(1, 10), HRFlowable(width="100%", thickness=0.5, color=RULE, spaceAfter=4),
            Paragraph(line, STYLES["caption"])]
