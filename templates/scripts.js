const SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info"];
const SEVERITY_COLORS = {
  Critical: "#f85149", High: "#ff9e42", Medium: "#e3c04d", Low: "#58a6ff", Info: "#8a97a8"
};

let currentFindings = [];
let severityChart = null;
let trendChart = null;
let activeScanId = null;

function fmtDuration(sec) {
  return (Math.round(sec * 100) / 100) + "s";
}

async function fetchJSON(url, opts) {
  const res = await fetch(url, opts);
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || ("Request failed: " + res.status));
  return data;
}

async function loadHistory() {
  const listEl = document.getElementById("historyList");
  try {
    const rows = await fetchJSON("/api/scans?limit=50");
    if (!rows.length) {
      listEl.innerHTML = '<div class="empty-state">No scans yet — run one to get started.</div>';
      return;
    }
    listEl.innerHTML = rows.map(r => `
      <div class="history-row${r.id === activeScanId ? ' active' : ''}" onclick="loadScanDetail(${r.id})">
        <span class="target">#${r.id} ${r.target_ip}</span>
        <span class="meta">${r.open_port_count} open · ${fmtDuration(r.scan_duration || 0)}</span>
      </div>
    `).join("");
  } catch (err) {
    listEl.innerHTML = `<div class="empty-state">Failed to load history: ${err.message}</div>`;
  }
}

async function loadScanDetail(scanId) {
  activeScanId = scanId;
  const metaEl = document.getElementById("detailMeta");
  try {
    const detail = await fetchJSON(`/api/scans/${scanId}`);
    currentFindings = detail.findings || [];
    metaEl.textContent = `Scan #${detail.id} · ${detail.target_ip} · ${detail.timestamp} · ${fmtDuration(detail.scan_duration || 0)}`;
    renderTable();
    renderSeverityChart(currentFindings);
    loadHistory(); // refresh highlight state
  } catch (err) {
    metaEl.textContent = `Failed to load scan: ${err.message}`;
  }
}

function renderTable() {
  const tbody = document.getElementById("resultsBody");
  const search = document.getElementById("searchInput").value.toLowerCase();
  const sevFilter = document.getElementById("severityFilter").value;

  let rows = currentFindings.filter(f => {
    if (sevFilter && f.severity !== sevFilter) return false;
    if (!search) return true;
    const haystack = `${f.port} ${f.service} ${f.remediation}`.toLowerCase();
    return haystack.includes(search);
  });

  rows.sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity));

  if (!rows.length) {
    tbody.innerHTML = '<tr><td colspan="5" class="empty-state">No matching findings.</td></tr>';
    return;
  }

  tbody.innerHTML = rows.map(f => `
    <tr>
      <td>${f.port}/tcp</td>
      <td>${f.service}${f.banner ? `<br><span style="color:var(--muted); font-size:11px;">${escapeHtml(f.banner)}</span>` : ""}</td>
      <td><span class="badge ${f.severity}">${f.severity}</span></td>
      <td>${escapeHtml(f.remediation)}</td>
      <td>${(f.cves || []).map(c => `<span class="cve-tag" title="${escapeHtml(c.summary)}">${c.cve_id} (${c.cvss_score})</span>`).join("") || "—"}</td>
    </tr>
  `).join("");
}

function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str || "";
  return div.innerHTML;
}

function renderSeverityChart(findings) {
  const counts = { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 };
  findings.forEach(f => { counts[f.severity] = (counts[f.severity] || 0) + 1; });

  const ctx = document.getElementById("severityChart");
  const data = {
    labels: SEVERITY_ORDER,
    datasets: [{
      data: SEVERITY_ORDER.map(s => counts[s]),
      backgroundColor: SEVERITY_ORDER.map(s => SEVERITY_COLORS[s]),
      borderColor: "#121821",
      borderWidth: 2,
    }]
  };
  if (severityChart) {
    severityChart.data = data;
    severityChart.update();
  } else {
    severityChart = new Chart(ctx, {
      type: "doughnut",
      data,
      options: {
        responsive: true, maintainAspectRatio: false,
        plugins: { legend: { position: "bottom", labels: { color: "#8a97a8", boxWidth: 10, font: { size: 10 } } } }
      }
    });
  }
}

async function loadTrendChart() {
  try {
    const stats = await fetchJSON("/api/stats");
    const recent = [...(stats.recent_scans || [])].reverse();
    const ctx = document.getElementById("trendChart");
    const data = {
      labels: recent.map(r => `#${r.id}`),
      datasets: [{
        label: "Open ports",
        data: recent.map(r => r.open_port_count),
        borderColor: "#3fb950",
        backgroundColor: "rgba(63,185,80,0.15)",
        tension: 0.25,
        fill: true,
        pointRadius: 3,
      }]
    };
    if (trendChart) {
      trendChart.data = data;
      trendChart.update();
    } else {
      trendChart = new Chart(ctx, {
        type: "line",
        data,
        options: {
          responsive: true, maintainAspectRatio: false,
          scales: {
            x: { ticks: { color: "#8a97a8", font: { size: 10 } }, grid: { color: "#232d3a" } },
            y: { beginAtZero: true, ticks: { color: "#8a97a8", stepSize: 1, font: { size: 10 } }, grid: { color: "#232d3a" } }
          },
          plugins: { legend: { display: false } }
        }
      });
    }
  } catch (err) {
    console.error("Failed to load trend stats:", err);
  }
}

async function triggerScan() {
  const btn = document.getElementById("scanBtn");
  const statusEl = document.getElementById("scanStatus");
  const target = document.getElementById("targetInput").value.trim();
  if (!target) {
    statusEl.textContent = "Enter a target first.";
    return;
  }

  const payload = {
    target,
    ports: document.getElementById("portsInput").value.trim() || "top",
    timeout: parseFloat(document.getElementById("timeoutInput").value) || 1.0,
    threads: parseInt(document.getElementById("threadsInput").value, 10) || 100,
    banner: document.getElementById("bannerInput").checked,
  };

  btn.disabled = true;
  statusEl.textContent = "Queuing scan…";

  try {
    const queued = await fetchJSON("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    statusEl.textContent = "Scanning " + target + " …";
    await pollJob(queued.queue_id, statusEl);
  } catch (err) {
    statusEl.textContent = "Error: " + err.message;
  } finally {
    btn.disabled = false;
  }
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

async function pollJob(queueId, statusEl) {
  for (let i = 0; i < 300; i++) {
    const job = await fetchJSON(`/api/scan/${queueId}`);
    if (job.status === "done") {
      statusEl.textContent = "Scan complete.";
      await loadHistory();
      await loadTrendChart();
      if (job.scan_ids && job.scan_ids.length) {
        loadScanDetail(job.scan_ids[job.scan_ids.length - 1]);
      }
      return;
    }
    if (job.status === "error") {
      statusEl.textContent = "Scan failed: " + (job.error || "unknown error");
      return;
    }
    await sleep(1000);
  }
  statusEl.textContent = "Scan is taking a while — check history shortly.";
}

async function init() {
  await loadHistory();
  await loadTrendChart();
  renderSeverityChart([]);
}
init();