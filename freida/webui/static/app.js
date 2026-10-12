"use strict";

// ---------------------------------------------------------------------------
// Markdown rendering. Reports quote strings and code from the analyzed binary,
// so everything is escaped; only the few tags the report generators emit
// (<br>, <b>, <code>, <details>, <summary>) are turned back into HTML.
// ---------------------------------------------------------------------------

function esc(text) {
  return String(text)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

const SAFE_TAGS = /&lt;(\/?)(br|b|code|strong|em)\s*\/?&gt;/g;

function inline(text) {
  const spans = [];
  const stash = (html) => `\u0000${spans.push(html) - 1}\u0000`;
  let out = String(text).replace(/`([^`]+)`/g, (_, code) => stash(`<code>${esc(code.replace(/\\\|/g, "|"))}</code>`));
  out = esc(out)
    .replace(/\\\|/g, "|")
    .replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>")
    .replace(/(^|[^\w*])\*([^*\s][^*]*?)\*(?![\w*])/g, "$1<em>$2</em>")
    .replace(SAFE_TAGS, "<$1$2>");
  return out.replace(/\u0000(\d+)\u0000/g, (_, n) => spans[Number(n)]);
}

function splitRow(line) {
  let row = line.trim();
  if (row.startsWith("|")) row = row.slice(1);
  if (row.endsWith("|") && !row.endsWith("\\|")) row = row.slice(0, -1);
  const cells = [];
  let cell = "";
  let inCode = false;
  for (let i = 0; i < row.length; i++) {
    const ch = row[i];
    if (ch === "\\" && row[i + 1] === "|") { cell += "\\|"; i++; continue; }
    if (ch === "`") inCode = !inCode;
    if (ch === "|" && !inCode) { cells.push(cell.trim()); cell = ""; continue; }
    cell += ch;
  }
  cells.push(cell.trim());
  return cells;
}

const FENCE = /^(\s*)```/;
const LIST_ITEM = /^(\s*)(?:[-*+]|\d+\.)\s+(.*)$/;
const TABLE_SEP = /^\s*\|?\s*:?-{3,}:?\s*(\|\s*:?-{3,}:?\s*)*\|?\s*$/;

function readFence(lines, i) {
  const indent = lines[i].match(FENCE)[1].length;
  const body = [];
  i++;
  while (i < lines.length && !/^\s*```\s*$/.test(lines[i])) {
    body.push(lines[i].slice(Math.min(indent, lines[i].search(/\S|$/))));
    i++;
  }
  return { html: `<pre><code>${esc(body.join("\n"))}</code></pre>`, next: i + 1 };
}

function isBlockStart(lines, i) {
  const line = lines[i];
  return FENCE.test(line) || /^#{1,6}\s/.test(line) || /^>/.test(line) || LIST_ITEM.test(line) ||
    /^\s*<\/?(details|summary)/.test(line) || /^(-{3,}|\*{3,})\s*$/.test(line) ||
    (line.trim().startsWith("|") && i + 1 < lines.length && TABLE_SEP.test(lines[i + 1]));
}

function joinLines(lines) {
  return lines.map((l, idx) => inline(l.replace(/\s+$/, "")) + (idx < lines.length - 1 ? (/ {2}$/.test(l) ? "<br>" : " ") : "")).join("");
}

function renderMarkdown(text) {
  const lines = String(text).replace(/\r\n?/g, "\n").split("\n");
  const out = [];
  let i = 0;
  while (i < lines.length) {
    const line = lines[i];
    const trimmed = line.trim();
    let m;
    if (trimmed === "") { i++; continue; }
    if (FENCE.test(line)) {
      const block = readFence(lines, i);
      out.push(block.html);
      i = block.next;
    } else if (trimmed === "<details>" || trimmed === "</details>") {
      out.push(trimmed);
      i++;
    } else if ((m = trimmed.match(/^<summary>(.*)<\/summary>$/))) {
      out.push(`<summary>${inline(m[1])}</summary>`);
      i++;
    } else if ((m = line.match(/^(#{1,6})\s+(.*)$/))) {
      out.push(`<h${m[1].length}>${inline(m[2].replace(/\s*#+\s*$/, ""))}</h${m[1].length}>`);
      i++;
    } else if (/^(-{3,}|\*{3,})\s*$/.test(trimmed)) {
      out.push("<hr>");
      i++;
    } else if (line.startsWith(">")) {
      const quote = [];
      while (i < lines.length && lines[i].startsWith(">")) quote.push(lines[i++].replace(/^>\s?/, ""));
      out.push(`<blockquote><p>${joinLines(quote)}</p></blockquote>`);
    } else if (trimmed.startsWith("|") && i + 1 < lines.length && TABLE_SEP.test(lines[i + 1])) {
      const header = splitRow(line);
      const align = splitRow(lines[i + 1]).map((c) => (c.endsWith(":") ? (c.startsWith(":") ? "center" : "right") : "left"));
      i += 2;
      const rows = [];
      while (i < lines.length && lines[i].trim().startsWith("|")) rows.push(splitRow(lines[i++]));
      const cell = (tag, c, idx) => `<${tag} class="al-${align[idx] || "left"}">${inline(c)}</${tag}>`;
      out.push(
        `<div class="table-wrap"><table><thead><tr>${header.map((c, idx) => cell("th", c, idx)).join("")}</tr></thead>` +
        `<tbody>${rows.map((r) => `<tr>${r.map((c, idx) => cell("td", c, idx)).join("")}</tr>`).join("")}</tbody></table></div>`
      );
    } else if (LIST_ITEM.test(line)) {
      const ordered = /^\s*\d+\./.test(line);
      const items = [];
      while (i < lines.length) {
        const cur = lines[i];
        const item = cur.match(LIST_ITEM);
        if (item) {
          items.push({ text: [item[2]], blocks: [] });
          i++;
        } else if (/^\s+\S/.test(cur) && FENCE.test(cur)) {
          const block = readFence(lines, i);
          items[items.length - 1].blocks.push(block.html);
          i = block.next;
        } else if (/^\s+\S/.test(cur)) {
          items[items.length - 1].text.push(cur.trim());
          i++;
        } else {
          break;
        }
      }
      const tag = ordered ? "ol" : "ul";
      out.push(`<${tag}>${items.map((it) => `<li>${joinLines(it.text)}${it.blocks.join("")}</li>`).join("")}</${tag}>`);
    } else {
      const para = [];
      while (i < lines.length && lines[i].trim() !== "" && (para.length === 0 || !isBlockStart(lines, i))) para.push(lines[i++]);
      out.push(`<p>${joinLines(para)}</p>`);
    }
  }
  return out.join("\n");
}

// ---------------------------------------------------------------------------
// UI
// ---------------------------------------------------------------------------

const $ = (id) => document.getElementById(id);
const state = { config: null, jobId: null, job: null, tab: null, pollTimer: null, fileCache: new Map() };

async function api(path, options = {}) {
  const headers = Object.assign({}, options.headers || {});
  if (options.method && options.method !== "GET") headers["X-Freida"] = "1";
  const res = await fetch(path, Object.assign({}, options, { headers }));
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `Request failed (${res.status})`);
  return data;
}

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") node.className = v;
    else if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
    else if (v !== false && v != null) node.setAttribute(k, v === true ? "" : v);
  }
  for (const child of children.flat()) {
    if (child != null) node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

function formatSize(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}

function formatTime(ts) {
  return ts ? new Date(ts * 1000).toLocaleString() : "";
}

function fileUrl(job, name, download = false) {
  return `/api/jobs/${job.id}/files/${encodeURIComponent(name)}${download ? "?download=1" : ""}`;
}

// --- form ------------------------------------------------------------------

function selectedBackend() {
  return document.querySelector("input[name=backend]:checked").value;
}

function updateForm() {
  const backend = selectedBackend();
  document.querySelectorAll("[data-backend]").forEach((node) => {
    node.hidden = !node.dataset.backend.split(" ").includes(backend);
  });
  const mock = backend === "mock";
  $("ai").disabled = mock;
  $("ai-mock-note").hidden = !mock;
  $("ai-options").hidden = mock || !$("ai").checked;
}

function setFile(file) {
  const zone = $("dropzone");
  const label = $("drop-label");
  label.textContent = "";
  if (file) {
    label.append(el("b", {}, file.name), el("br"), el("small", {}, `${formatSize(file.size)} · click to change`));
    zone.classList.add("has-file");
  } else {
    label.append("Drop an executable here or ", el("u", {}, "browse"), el("br"), el("small", {}, "ELF, PE or Mach-O"));
    zone.classList.remove("has-file");
  }
}

function collectParams(form) {
  const data = new FormData(form);
  const params = new URLSearchParams();
  for (const key of ["backend", "ghidra_dir", "server_url", "mcp_cmd", "max_functions", "decompile_timeout",
    "timeout", "model", "thinking", "max_tool_calls", "max_cost"]) {
    const value = data.get(key);
    if (value != null && String(value).trim() !== "") params.set(key, String(value).trim());
  }
  if (!form.elements.pdf.checked) params.set("no_pdf", "1");
  if (form.elements.verbose.checked) params.set("verbose", "1");
  if (form.elements.ai.checked && !form.elements.ai.disabled) {
    params.set("ai", "1");
    if (form.elements.ai_dry_run.checked) params.set("ai_dry_run", "1");
  }
  return params;
}

async function submitJob(useSample) {
  const form = $("analyze-form");
  const file = $("file").files[0];
  $("form-error").textContent = "";
  if (!useSample && !file) {
    $("form-error").textContent = "Choose a file to analyze.";
    return;
  }
  const maxBytes = state.config.max_upload_mb * 1024 * 1024;
  if (!useSample && file.size > maxBytes) {
    $("form-error").textContent = `The file is larger than ${state.config.max_upload_mb} MB.`;
    return;
  }
  const params = collectParams(form);
  const headers = { "Content-Type": "application/octet-stream" };
  const key = $("gemini_key").value.trim();
  if (params.get("ai") && key) headers["X-Gemini-Key"] = key;
  if (useSample) params.set("sample", "1");
  else params.set("filename", file.name);

  $("submit").disabled = true;
  try {
    const job = await api(`/api/jobs?${params}`, { method: "POST", headers, body: useSample ? "" : file });
    state.tab = null;
    await loadHistory();
    await selectJob(job.id);
  } catch (err) {
    $("form-error").textContent = err.message;
  } finally {
    $("submit").disabled = false;
  }
}

// --- history ---------------------------------------------------------------

async function loadHistory() {
  const { jobs } = await api("/api/jobs");
  const list = $("history");
  list.textContent = "";
  if (!jobs.length) list.append(el("li", { class: "hint" }, "No analyses yet."));
  for (const job of jobs) {
    list.append(el("li", {},
      el("button", { type: "button", class: job.id === state.jobId ? "active" : "", onclick: () => selectJob(job.id) },
        el("span", { class: "name" }, job.filename),
        el("span", { class: `badge ${job.status}` }, job.status))));
  }
}

// --- job view --------------------------------------------------------------

async function selectJob(id) {
  clearTimeout(state.pollTimer);
  if (state.jobId !== id) state.tab = null;
  state.jobId = id;
  document.querySelectorAll("#history button").forEach((b) => b.classList.remove("active"));
  await refreshJob();
  loadHistory().catch(() => {});
}

async function refreshJob() {
  const id = state.jobId;
  let job;
  try {
    job = await api(`/api/jobs/${id}`);
  } catch (err) {
    $("job").hidden = true;
    $("empty").hidden = false;
    return;
  }
  if (id !== state.jobId) return;
  const wasActive = state.job && state.job.id === id && ["queued", "running"].includes(state.job.status);
  const active = ["queued", "running"].includes(job.status);
  if (wasActive && !active && job.status === "done") state.tab = null;  // show the report once it is ready
  state.job = job;
  renderJob(job);
  if (active) state.pollTimer = setTimeout(refreshJob, 1500);
  else if (wasActive) loadHistory().catch(() => {});
}

function tabsFor(job) {
  const tabs = [];
  const files = job.outputs;
  const syscall = files.find((f) => f.kind === "syscall_report");
  const ai = files.find((f) => f.kind === "ai_report");
  if (syscall) tabs.push({ id: "syscall", label: "Syscall report", file: syscall });
  if (ai) tabs.push({ id: "ai", label: "AI overview", file: ai });
  for (const pdf of files.filter((f) => f.name.endsWith(".pdf"))) {
    tabs.push({ id: `pdf:${pdf.name}`, label: pdf.name.includes("_overview") ? "AI overview PDF" : "Syscall PDF", pdf });
  }
  tabs.push({ id: "log", label: "Log" });
  tabs.push({ id: "files", label: `Files (${files.length})` });
  return tabs;
}

function renderJob(job) {
  $("empty").hidden = true;
  $("job").hidden = false;
  $("job-title").textContent = job.filename;
  const backendName = { pyghidra: "PyGhidra", mcp: "Ghidra MCP", mock: "Mock" }[job.backend] || job.backend;
  $("job-meta").textContent = `${backendName}${job.ai ? " + AI overview" : ""} · started ${formatTime(job.created)}` +
    (job.finished ? ` · finished ${formatTime(job.finished)}` : "");
  const status = $("job-status");
  status.textContent = job.status;
  status.className = `badge ${job.status}`;
  $("cancel").hidden = !["queued", "running"].includes(job.status);
  $("job-error").textContent = job.error || "";

  const steps = $("steps");
  steps.textContent = "";
  for (const step of job.steps) {
    const took = step.finished ? ` (${Math.max(0, step.finished - step.started).toFixed(1)}s)` : "";
    steps.append(el("li", { class: step.status }, `${step.name}: ${step.status}${took}`));
  }

  const tabs = tabsFor(job);
  const active = ["queued", "running"].includes(job.status);
  if (!state.tab || !tabs.some((t) => t.id === state.tab)) {
    state.tab = active ? "log" : (tabs.find((t) => t.id === "syscall" || t.id === "ai") || tabs.find((t) => t.id === "log")).id;
  }
  const nav = $("tabs");
  nav.textContent = "";
  for (const tab of tabs) {
    nav.append(el("button", {
      type: "button", role: "tab", class: tab.id === state.tab ? "active" : "",
      onclick: () => { state.tab = tab.id; renderJob(state.job); },
    }, tab.label));
  }
  renderTab(job, tabs.find((t) => t.id === state.tab));
}

async function renderTab(job, tab) {
  const body = $("tab-body");
  const key = `${job.id}:${tab.id}`;
  if (tab.id === "log") {
    const atBottom = body.dataset.key !== key || !body.firstChild || body.firstChild.scrollTop + body.firstChild.clientHeight >= body.firstChild.scrollHeight - 20;
    const pre = body.dataset.key === key && body.firstChild ? body.firstChild : el("pre", { class: "log" });
    pre.textContent = job.log || "(no output yet)";
    if (body.firstChild !== pre) { body.textContent = ""; body.append(pre); }
    body.dataset.key = key;
    if (atBottom) pre.scrollTop = pre.scrollHeight;
    return;
  }
  if (tab.id === "files") {
    if (body.dataset.key === key && body.dataset.count === String(job.outputs.length)) return;
    body.dataset.key = key;
    body.dataset.count = String(job.outputs.length);
    body.textContent = "";
    if (!job.outputs.length) { body.append(el("p", { class: "hint" }, "No output files yet.")); return; }
    body.append(el("table", { class: "files" }, job.outputs.map((f) => el("tr", {},
      el("td", {}, el("a", { href: fileUrl(job, f.name), target: "_blank", rel: "noopener" }, f.name)),
      el("td", { class: "meta" }, formatSize(f.size)),
      el("td", {}, el("a", { href: fileUrl(job, f.name, true) }, "Download"))))));
    return;
  }
  if (tab.pdf) {
    if (body.dataset.key === key) return;
    body.dataset.key = key;
    body.textContent = "";
    body.append(
      el("div", { class: "toolbar" },
        el("a", { href: fileUrl(job, tab.pdf.name), target: "_blank", rel: "noopener" }, "Open in new tab"),
        el("a", { href: fileUrl(job, tab.pdf.name, true) }, "Download")),
      el("iframe", { class: "pdf-frame", src: fileUrl(job, tab.pdf.name), title: tab.pdf.name }));
    return;
  }
  const file = tab.file;
  const cacheKey = `${job.id}:${file.name}:${file.size}`;
  if (body.dataset.key === cacheKey) return;
  body.dataset.key = cacheKey;
  let text = state.fileCache.get(cacheKey);
  if (text == null) {
    const res = await fetch(fileUrl(job, file.name));
    text = res.ok ? await res.text() : `Could not load ${file.name}.`;
    state.fileCache.set(cacheKey, text);
  }
  if (body.dataset.key !== cacheKey) return;
  const doc = el("div", { class: "md" });
  doc.innerHTML = renderMarkdown(text);
  body.textContent = "";
  body.append(
    el("div", { class: "toolbar" },
      el("a", { href: fileUrl(job, file.name, true) }, `Download ${file.name}`)),
    doc);
}

// --- startup ---------------------------------------------------------------

function pill(text, kind) {
  return el("span", { class: `pill ${kind || ""}` }, text);
}

async function init() {
  const config = await api("/api/config");
  state.config = config;
  const env = $("env-status");
  env.append(
    pill(config.ghidra_install_dir ? "Ghidra configured" : "GHIDRA_INSTALL_DIR not set", config.ghidra_install_dir ? "ok" : "warn"),
    pill(config.pyghidra_installed ? "PyGhidra installed" : "PyGhidra not installed", config.pyghidra_installed ? "ok" : "warn"),
    pill(config.gemini_key_set ? "Gemini key set" : "No Gemini key", config.gemini_key_set ? "ok" : ""));

  const d = config.defaults;
  $("ghidra_dir").placeholder = config.ghidra_install_dir || "GHIDRA_INSTALL_DIR";
  $("model").value = d.model;
  $("max_tool_calls").value = d.max_tool_calls;
  $("max_cost").value = d.max_cost;
  for (const level of d.thinking_levels) $("thinking").append(el("option", { value: level, selected: level === d.thinking }, level));
  $("key-hint").textContent = config.gemini_key_set ? "(optional: the server already has GEMINI_API_KEY)" : "(required unless dry run)";
  $("use-sample").hidden = !config.sample_available;
  if (!config.pyghidra_installed || !config.ghidra_install_dir) {
    document.querySelector("input[name=backend][value=mock]").checked = true;
  }

  const form = $("analyze-form");
  form.addEventListener("change", updateForm);
  form.addEventListener("submit", (e) => { e.preventDefault(); submitJob(false); });
  $("use-sample").addEventListener("click", () => submitJob(true));
  $("file").addEventListener("change", () => setFile($("file").files[0]));
  const zone = $("dropzone");
  zone.addEventListener("dragover", (e) => { e.preventDefault(); zone.classList.add("drag"); });
  zone.addEventListener("dragleave", () => zone.classList.remove("drag"));
  zone.addEventListener("drop", (e) => {
    e.preventDefault();
    zone.classList.remove("drag");
    if (e.dataTransfer.files.length) {
      $("file").files = e.dataTransfer.files;
      setFile(e.dataTransfer.files[0]);
    }
  });
  $("cancel").addEventListener("click", async () => {
    await api(`/api/jobs/${state.jobId}/cancel`, { method: "POST" }).catch((err) => alert(err.message));
    refreshJob();
  });
  $("delete").addEventListener("click", async () => {
    if (!confirm("Delete this job and its reports?")) return;
    await api(`/api/jobs/${state.jobId}`, { method: "DELETE" }).catch((err) => alert(err.message));
    clearTimeout(state.pollTimer);
    state.jobId = null;
    state.job = null;
    $("job").hidden = true;
    $("empty").hidden = false;
    loadHistory();
  });
  updateForm();

  await loadHistory();
  const latest = document.querySelector("#history button");
  if (latest) latest.click();
}

if (typeof document !== "undefined") {
  document.addEventListener("DOMContentLoaded", () => {
    init().catch((err) => { $("form-error").textContent = `Could not reach the server: ${err.message}`; });
  });
}
if (typeof module !== "undefined") module.exports = { renderMarkdown, inline, esc };
