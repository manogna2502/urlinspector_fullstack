const API_BASE = window.API_BASE || "";

const els = {
  form: document.getElementById("scanForm"),
  input: document.getElementById("linkInput"),
  btn: document.getElementById("scanBtn"),
  consoleLog: document.getElementById("console-log"),
  logLines: document.getElementById("logLines"),
  verdictCard: document.getElementById("verdictCard"),
  verdictBadge: document.getElementById("verdictBadge"),
  verdictDomain: document.getElementById("verdictDomain"),
  cacheBadge: document.getElementById("cacheBadge"),
  scoreBar: document.getElementById("scoreBar"),
  scoreNumber: document.getElementById("scoreNumber"),
  signalGrid: document.getElementById("signalGrid"),
  visitLink: document.getElementById("visitLink"),
  reportLink: document.getElementById("reportLink"),
  historyToggle: document.getElementById("historyToggle"),
  historyPanel: document.getElementById("historyPanel"),
  historyList: document.getElementById("historyList"),
  exportBtn: document.getElementById("exportBtn"),
  clearBtn: document.getElementById("clearBtn"),
  statsGrid: document.getElementById("statsGrid"),
  statTotal: document.getElementById("statTotal"),
  statDomains: document.getElementById("statDomains"),
  statFlagged: document.getElementById("statFlagged"),
  statCached: document.getElementById("statCached"),
};

const STEP_SCRIPT = [
  { text: "$ resolving DNS records...", delay: 150 },
  { text: "$ querying WHOIS registry...", delay: 550 },
  { text: "$ inspecting TLS certificate...", delay: 950 },
  { text: "$ cross-checking reputation signals...", delay: 1350 },
];

let pollTimer = null;
let stepTimers = [];

els.form.addEventListener("submit", onSubmit);
els.historyToggle.addEventListener("click", toggleHistory);
els.exportBtn.addEventListener("click", exportHistory);
els.clearBtn.addEventListener("click", clearHistory);

loadHistory();
loadStats();

async function onSubmit(e) {
  e.preventDefault();
  const url = els.input.value.trim();
  if (!url) return;

  resetPanels();
  setBusy(true);
  startLogAnimation();

  try {
    const res = await fetch(`${API_BASE}/api/inspect`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    });

    if (res.status === 429) {
      stopLogAnimation();
      pushLog("$ rate limit hit — slow down and try again shortly", "err");
      setBusy(false);
      return;
    }
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || `Request failed (${res.status})`);
    }

    const data = await res.json();
    pollJob(data.job_id);
  } catch (err) {
    stopLogAnimation();
    pushLog(`$ error: ${err.message}`, "err");
    setBusy(false);
  }
}

function pollJob(jobId) {
  clearInterval(pollTimer);
  pollTimer = setInterval(async () => {
    try {
      const res = await fetch(`${API_BASE}/api/jobs/${jobId}`);
      if (!res.ok) throw new Error("job lookup failed");
      const job = await res.json();

      if (job.status === "done") {
        clearInterval(pollTimer);
        stopLogAnimation();
        pushLog(`$ scan complete — verdict: ${job.verdict}`, verdictLogClass(job.verdict));
        renderVerdict(job);
        loadHistory();
        loadStats();
        setBusy(false);
      } else if (job.status === "error") {
        clearInterval(pollTimer);
        stopLogAnimation();
        pushLog(`$ scan failed: ${job.error_message || "unknown error"}`, "err");
        setBusy(false);
      }
      // pending/running -> keep polling, scripted log lines carry the UI meanwhile
    } catch (err) {
      clearInterval(pollTimer);
      stopLogAnimation();
      pushLog(`$ error polling job: ${err.message}`, "err");
      setBusy(false);
    }
  }, 900);
}

function verdictLogClass(verdict) {
  if (verdict === "safe") return "ok";
  if (verdict === "suspicious") return "warn";
  return "err";
}

function startLogAnimation() {
  els.consoleLog.hidden = false;
  els.logLines.innerHTML = "";
  stepTimers = STEP_SCRIPT.map((step) =>
    setTimeout(() => pushLog(step.text), step.delay)
  );
}

function stopLogAnimation() {
  stepTimers.forEach(clearTimeout);
  stepTimers = [];
}

function pushLog(text, cls = "") {
  const line = document.createElement("div");
  line.className = `log-line ${cls}`;
  line.textContent = text;
  els.logLines.appendChild(line);
}

function setBusy(isBusy) {
  els.btn.disabled = isBusy;
  els.btn.querySelector(".btn-label").textContent = isBusy ? "Scanning..." : "Run scan";
}

function resetPanels() {
  els.verdictCard.hidden = true;
  els.consoleLog.hidden = true;
  els.logLines.innerHTML = "";
}

function renderVerdict(job) {
  els.verdictCard.hidden = false;
  els.verdictBadge.textContent = job.verdict;
  els.verdictBadge.className = `verdict-badge ${job.verdict}`;
  els.verdictDomain.textContent = job.domain;
  els.cacheBadge.hidden = !job.from_cache;

  const score = job.risk_score ?? 0;
  els.scoreBar.style.width = `${score}%`;
  els.scoreNumber.textContent = Math.round(score);

  els.signalGrid.innerHTML = "";
  const d = job.details || {};

  addSignal("DNS", d.dns?.resolved ? (d.dns.a_records[0] || "resolved") : "unresolved");
  addSignal("Domain age", d.whois?.age_days != null ? `${d.whois.age_days} days` : "unknown");
  addSignal("TLS cert", d.ssl?.has_cert ? (d.ssl.issuer || "present") : "none/failed");
  const kw = d.reputation?.blacklist?.matched_keywords || [];
  addSignal("Flags", buildFlagSummary(d));

  els.visitLink.href = job.url;
  els.reportLink.hidden = job.verdict === "safe";
}

function buildFlagSummary(d) {
  const flags = [];
  if (d.reputation?.blacklist?.is_blacklisted) flags.push("blacklisted");
  if (d.reputation?.blacklist?.suspicious_tld) flags.push("odd TLD");
  if (d.reputation?.blacklist?.matched_keywords?.length) flags.push("keyword match");
  if (d.reputation?.safe_browsing?.threats_found?.length) flags.push("Safe Browsing hit");
  return flags.length ? flags.join(", ") : "none";
}

function addSignal(label, value) {
  const wrap = document.createElement("div");
  wrap.className = "signal";
  wrap.innerHTML = `<div class="signal-label">${label}</div><div class="signal-value">${escapeHtml(String(value))}</div>`;
  els.signalGrid.appendChild(wrap);
}

function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str;
  return div.innerHTML;
}

function toggleHistory() {
  els.historyPanel.hidden = !els.historyPanel.hidden;
  if (!els.historyPanel.hidden) loadHistory();
}

async function loadStats() {
  try {
    const res = await fetch(`${API_BASE}/api/history/stats`);
    if (!res.ok) return;
    const stats = await res.json();

    if (!stats.total_scans) {
      els.statsGrid.hidden = true;
      return;
    }

    els.statsGrid.hidden = false;
    els.statTotal.textContent = stats.total_scans;
    els.statDomains.textContent = stats.unique_domains;
    els.statCached.textContent = stats.cache_hits;
    const flagged = (stats.verdicts?.suspicious || 0) + (stats.verdicts?.malicious || 0);
    els.statFlagged.textContent = flagged;
  } catch (err) {
    // stats are a nice-to-have; fail quietly
  }
}

async function loadHistory() {
  try {
    const res = await fetch(`${API_BASE}/api/history?limit=50`);
    if (!res.ok) return;
    const items = await res.json();
    renderHistory(items);
  } catch (err) {
    // history is a nice-to-have; fail quietly
  }
}

function renderHistory(items) {
  els.historyList.innerHTML = "";
  if (!items.length) {
    els.historyList.innerHTML = `<li class="history-empty">No scans yet.</li>`;
    return;
  }
  items.forEach((item) => {
    const li = document.createElement("li");
    li.className = "history-item";
    const status = item.verdict || item.status;
    li.innerHTML = `
      <span class="history-verdict ${status}">${status}</span>
      <a href="${item.url}" target="_blank" rel="noopener">${item.domain}</a>
    `;
    els.historyList.appendChild(li);
  });
}

async function exportHistory() {
  try {
    const res = await fetch(`${API_BASE}/api/history/export`);
    const data = await res.json();
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "url-inspector-history.json";
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  } catch (err) {
    alert("Could not export history.");
  }
}

async function clearHistory() {
  if (!confirm("Clear all scan history? This can't be undone.")) return;
  try {
    await fetch(`${API_BASE}/api/history`, { method: "DELETE" });
    loadHistory();
  } catch (err) {
    alert("Could not clear history.");
  }
}