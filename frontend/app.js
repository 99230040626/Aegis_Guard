/**
 * Aegis Guard – Frontend Application (ES6+)
 *
 * Responsibilities:
 *  - Connect to the backend via Socket.IO for real-time scan results
 *  - Handle manual URL scan form submission
 *  - Render the latest scan result with a risk progress bar
 *  - Maintain and render the scan history table
 *  - Show / hide phishing alert banners automatically
 *  - Update connection status indicator
 *  - Track running stats (total / safe / warning / malicious)
 */

"use strict";

// ── Constants ────────────────────────────────────────────────────────────────

const STATUS_SAFE      = "safe";
const STATUS_WARNING   = "warning";
const STATUS_MALICIOUS = "malicious";

// Maximum rows shown in the history table
const MAX_HISTORY_ROWS = 50;

// ── DOM refs ─────────────────────────────────────────────────────────────────

const connectionDot    = document.getElementById("connection-dot");
const connectionLabel  = document.getElementById("connection-label");
const alertBanner      = document.getElementById("alert-banner");
const alertMessage     = document.getElementById("alert-message");
const alertCloseBtn    = document.getElementById("alert-close-btn");
const scanForm         = document.getElementById("scan-form");
const urlInput         = document.getElementById("url-input");
const scanBtn          = document.getElementById("scan-btn");
const formError        = document.getElementById("form-error");
const liveResultSection= document.getElementById("live-result-section");
const resultUrl        = document.getElementById("result-url");
const resultStatus     = document.getElementById("result-status");
const resultScore      = document.getElementById("result-score");
const resultTime       = document.getElementById("result-time");
const progressBar      = document.getElementById("progress-bar");
const featureRow       = document.getElementById("feature-row");
const statTotal        = document.getElementById("stat-total");
const statSafe         = document.getElementById("stat-safe");
const statWarning      = document.getElementById("stat-warning");
const statMalicious    = document.getElementById("stat-malicious");
const historyTbody     = document.getElementById("history-tbody");
const clearLogBtn      = document.getElementById("clear-log-btn");

// ── State ────────────────────────────────────────────────────────────────────

const stats = { total: 0, safe: 0, warning: 0, malicious: 0 };
let historyRows = [];   // Array of result objects for the table
let alertTimeout = null;

// ── Socket.IO connection ──────────────────────────────────────────────────────

const socket = io();   // connects to the server that served this page

socket.on("connect", () => {
  setConnectionState("connected");
});

socket.on("disconnect", () => {
  setConnectionState("disconnected");
});

socket.on("connect_error", () => {
  setConnectionState("disconnected");
});

// Initial history sent when we first connect
socket.on("log_history", (entries) => {
  if (!Array.isArray(entries)) return;
  // Replay history (oldest first so the table order is consistent)
  [...entries].reverse().forEach(handleScanResult);
});

// Live scan result pushed from the backend
socket.on("scan_result", (result) => {
  handleScanResult(result);
});

// ── Core result handler ───────────────────────────────────────────────────────

/**
 * Process a scan result object received from the server.
 * Updates stats, live result view, history table, and alert banner.
 * @param {object} result
 */
function handleScanResult(result) {
  if (!result || result.error) return;

  const { url, risk_score, status, timestamp, features } = result;

  // ── 1. Update stats
  stats.total += 1;
  if (status === STATUS_SAFE)           stats.safe      += 1;
  else if (status === STATUS_WARNING)   stats.warning   += 1;
  else if (status === STATUS_MALICIOUS) stats.malicious += 1;
  renderStats();

  // ── 2. Update live result panel
  renderLiveResult(result);

  // ── 3. Prepend to history table
  historyRows.unshift(result);
  if (historyRows.length > MAX_HISTORY_ROWS) historyRows.length = MAX_HISTORY_ROWS;
  renderHistoryTable();

  // ── 4. Show alert banner for warning / malicious
  if (status === STATUS_MALICIOUS || status === STATUS_WARNING) {
    showAlertBanner(url, status, risk_score);
  }
}

// ── Render helpers ────────────────────────────────────────────────────────────

function renderStats() {
  statTotal.textContent    = stats.total;
  statSafe.textContent     = stats.safe;
  statWarning.textContent  = stats.warning;
  statMalicious.textContent= stats.malicious;
}

function renderLiveResult(result) {
  const { url, risk_score, status, timestamp, features } = result;

  liveResultSection.hidden = false;

  resultUrl.textContent   = url;
  resultStatus.textContent= statusLabel(status);
  resultStatus.className  = `result-status badge badge--${status || "error"}`;
  resultScore.textContent = `Risk: ${risk_score}%`;
  resultTime.textContent  = formatTimestamp(timestamp);

  // Progress bar
  progressBar.style.width   = `${risk_score}%`;
  progressBar.className     = `progress-bar progress-bar--${status || "error"}`;

  // Feature details
  if (features) {
    featureRow.innerHTML = `
      <div class="feature-item">
        <span class="feature-label">URL Length</span>
        <span class="feature-value">${features.url_length}</span>
      </div>
      <div class="feature-item">
        <span class="feature-label">Special Chars</span>
        <span class="feature-value">${features.special_count}</span>
      </div>
      <div class="feature-item">
        <span class="feature-label">Suspicious Keywords</span>
        <span class="feature-value">${features.keyword_count}</span>
      </div>
    `;
  } else {
    featureRow.innerHTML = "";
  }
}

function renderHistoryTable() {
  if (historyRows.length === 0) {
    historyTbody.innerHTML = `
      <tr class="empty-row">
        <td colspan="4">No scans yet – waiting for results…</td>
      </tr>`;
    return;
  }

  historyTbody.innerHTML = historyRows.map((r, idx) => {
    const rowClass = idx === 0 ? "row-new" : "";
    return `
      <tr class="${rowClass}">
        <td>${formatTimestamp(r.timestamp)}</td>
        <td class="td-url" title="${escapeHtml(r.url)}">${escapeHtml(r.url)}</td>
        <td><span class="badge badge--${r.status}">${statusLabel(r.status)}</span></td>
        <td class="td-score td-score--${r.status}">${r.risk_score}%</td>
      </tr>`;
  }).join("");
}

// ── Alert Banner ──────────────────────────────────────────────────────────────

function showAlertBanner(url, status, riskScore) {
  const label = status === STATUS_MALICIOUS ? "🚨 Malicious" : "⚠️ Warning";
  alertMessage.textContent = `${label} URL detected! Risk: ${riskScore}% — ${truncate(url, 60)}`;
  alertBanner.classList.remove("alert-banner--hidden");

  // Auto-dismiss after 8 seconds
  if (alertTimeout) clearTimeout(alertTimeout);
  alertTimeout = setTimeout(hideAlertBanner, 8000);
}

function hideAlertBanner() {
  alertBanner.classList.add("alert-banner--hidden");
}

alertCloseBtn.addEventListener("click", hideAlertBanner);

// ── Connection state ──────────────────────────────────────────────────────────

function setConnectionState(state) {
  connectionDot.className = `dot dot--${state}`;
  const labels = { connected: "Connected", disconnected: "Disconnected", connecting: "Connecting…" };
  connectionLabel.textContent = labels[state] || state;
}

// Start as connecting
setConnectionState("connecting");

// ── Manual scan form ──────────────────────────────────────────────────────────

scanForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  formError.textContent = "";

  const rawUrl = urlInput.value.trim();
  if (!rawUrl) {
    formError.textContent = "Please enter a URL.";
    return;
  }
  if (!/^https?:\/\//i.test(rawUrl)) {
    formError.textContent = "URL must start with http:// or https://";
    return;
  }

  scanBtn.disabled = true;
  scanBtn.textContent = "Scanning…";

  try {
    const res = await fetch("/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: rawUrl }),
    });

    const data = await res.json();

    if (!res.ok) {
      formError.textContent = data.error || "Server error. Please try again.";
    }
    // The result is broadcast via Socket.IO so handleScanResult() will pick it up
  } catch (err) {
    formError.textContent = "Network error – is the server running?";
    console.error("[Aegis Guard] Scan error:", err);
  } finally {
    scanBtn.disabled = false;
    scanBtn.innerHTML = '<span class="btn-icon">🔍</span> Scan';
    urlInput.value = "";
  }
});

// ── Clear log ─────────────────────────────────────────────────────────────────

clearLogBtn.addEventListener("click", () => {
  historyRows.length = 0;
  stats.total = stats.safe = stats.warning = stats.malicious = 0;
  renderStats();
  renderHistoryTable();
  liveResultSection.hidden = true;
  hideAlertBanner();
});

// ── Utility functions ─────────────────────────────────────────────────────────

function statusLabel(status) {
  const labels = {
    [STATUS_SAFE]:      "Safe",
    [STATUS_WARNING]:   "Warning",
    [STATUS_MALICIOUS]: "Malicious",
  };
  return labels[status] || status;
}

function formatTimestamp(iso) {
  if (!iso) return "—";
  try {
    const d = new Date(iso);
    return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
  } catch {
    return iso;
  }
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function truncate(str, max) {
  return str.length > max ? str.slice(0, max) + "…" : str;
}
