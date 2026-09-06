/**
 * CyberShield Extension Popup Script – v2.0
 * Queries background worker for cached result, renders all 4 outcome states.
 */

const API_BASE = 'https://cybershield-backend-uhwn.onrender.com/api';
const DASHBOARD_URL = 'https://cybershield-backend-uhwn.onrender.com';

// ── Outcome config ───────────────────────────────────────────────────────────
const OUTCOMES = {
  KNOWN_THREAT: {
    icon: '🚨',
    label: 'Known Threat',
    theme: 'threat',
    showSaveAlert: true
  },
  SUSPICIOUS: {
    icon: '⚠️',
    label: 'Suspicious Site',
    theme: 'suspicious',
    showSaveAlert: true
  },
  NO_THREAT: {
    icon: '✅',
    label: 'No Threat Found',
    theme: 'safe',
    showSaveAlert: false
  },
  CHECK_FAILED: {
    icon: '❓',
    label: 'Unable to Check',
    theme: 'failed',
    showSaveAlert: false
  }
};

// ── State ────────────────────────────────────────────────────────────────────
let currentDomain = null;
let currentResult = null;

// ── Init ─────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', async () => {
  // Pause state
  const pauseState = await sendMsg({ action: 'getPauseState' });
  renderPauseState(pauseState && pauseState.protectionPaused);

  // Get active tab
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const url = tab?.url || '';

  // Handle internal/system pages
  if (!url || !url.startsWith('http')) {
    showSystemPage();
    return;
  }

  try {
    const urlObj = new URL(url);
    currentDomain = urlObj.hostname.replace(/^www\./, '');
    const isHttps = urlObj.protocol === 'https:';

    // Set domain display
    document.getElementById('domain-text').textContent = currentDomain;
    document.getElementById('domain-protocol-icon').textContent = isHttps ? '🔒' : '⚠️';

    // Try background cache first
    const cached = await sendMsg({ action: 'getResult', domain: currentDomain });
    if (cached && cached.success && cached.result) {
      currentResult = cached.result;
      renderResult(currentResult);
    } else {
      // Fetch from backend
      await performCheck(currentDomain, isHttps);
    }
  } catch (err) {
    renderOutcome('CHECK_FAILED', 'Unable to parse page URL.', '');
  }

  // ── Pause toggle ────────────────────────────────────────────────────────
  document.getElementById('btn-pause').addEventListener('click', async () => {
    const state = await sendMsg({ action: 'togglePause' });
    renderPauseState(state && state.protectionPaused);
  });

  // ── Run Full Scan ────────────────────────────────────────────────────────
  document.getElementById('btn-full-scan').addEventListener('click', () => {
    const target = currentDomain ? `${DASHBOARD_URL}/scanner.html?url=https://${currentDomain}` : `${DASHBOARD_URL}/scanner.html`;
    chrome.tabs.create({ url: target });
  });

  // ── Save Alert ───────────────────────────────────────────────────────────
  document.getElementById('btn-save-alert').addEventListener('click', async () => {
    if (!currentResult || !currentDomain) return;
    const btn = document.getElementById('btn-save-alert');
    btn.disabled = true;
    btn.textContent = 'Saving…';
    try {
      // Get auth token from storage (set when user logs into dashboard)
      const stored = await chrome.storage.local.get('csAuthToken');
      const token = stored.csAuthToken;
      if (!token) {
        btn.textContent = 'Login Required';
        setTimeout(() => { btn.disabled = false; btn.textContent = '💾 Save Alert'; }, 2500);
        return;
      }
      const res = await fetch(`${API_BASE}/extension/alert`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
        body: JSON.stringify({
          domain: currentDomain,
          outcome: currentResult.outcome,
          reason: currentResult.reason,
          source: currentResult.source
        })
      });
      const data = await res.json();
      if (data.success) {
        showAlertSaved();
      } else {
        btn.textContent = 'Login Required';
        setTimeout(() => { btn.disabled = false; btn.textContent = '💾 Save Alert'; }, 2500);
      }
    } catch (_) {
      btn.disabled = false;
      btn.textContent = '💾 Save Alert';
    }
  });

  // ── Report false positive ─────────────────────────────────────────────────
  document.getElementById('btn-report').addEventListener('click', async () => {
    if (!currentDomain) return;
    const btn = document.getElementById('btn-report');
    btn.disabled = true;
    btn.textContent = 'Sending…';
    try {
      await fetch(`${API_BASE}/extension/report-false-positive`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain: currentDomain, outcome: currentResult?.outcome || 'unknown' })
      });
      btn.textContent = '✓ Reported';
      setTimeout(() => { btn.disabled = false; btn.textContent = '⚑ Report Incorrect'; }, 3000);
    } catch (_) {
      btn.disabled = false;
      btn.textContent = '⚑ Report Incorrect';
    }
  });

  // ── Recheck ───────────────────────────────────────────────────────────────
  document.getElementById('btn-refresh').addEventListener('click', async () => {
    if (!currentDomain) return;
    showLoading();
    await sendMsg({ action: 'forceCheck', domain: currentDomain });
    await performCheck(currentDomain, document.getElementById('domain-protocol-icon').textContent === '🔒');
  });
});

// ── Check domain directly from popup ─────────────────────────────────────────
async function performCheck(domain, isHttps) {
  showLoading();
  try {
    const res = await fetch(`${API_BASE}/extension/check`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ domain, isHttps })
    });
    const json = await res.json();
    if (json.success && json.data) {
      currentResult = json.data;
      renderResult(currentResult);
    } else {
      renderOutcome('CHECK_FAILED', 'Server returned an unexpected response.', '');
    }
  } catch (_) {
    renderOutcome('CHECK_FAILED', 'Could not reach CyberShield backend. Check your connection.', '');
  }
}

// ── Render helpers ────────────────────────────────────────────────────────────
function showLoading() {
  document.getElementById('state-loading').style.display = 'flex';
  document.getElementById('state-result').style.display = 'none';
  document.getElementById('state-system').style.display = 'none';
  document.getElementById('footer-actions').style.display = 'none';
  document.getElementById('outcome-card').className = 'outcome-card';
}

function showSystemPage() {
  document.getElementById('domain-text').textContent = 'Internal Browser Page';
  document.getElementById('domain-protocol-icon').textContent = '🔵';
  document.getElementById('state-loading').style.display = 'none';
  document.getElementById('state-result').style.display = 'none';
  document.getElementById('state-system').style.display = 'flex';
  document.getElementById('outcome-card').className = 'outcome-card neutral';
}

function renderResult(result) {
  renderOutcome(result.outcome, result.reason, result.source, result.checkedAt);
}

function renderOutcome(outcome, reason, source, checkedAt) {
  const config = OUTCOMES[outcome] || OUTCOMES.CHECK_FAILED;

  document.getElementById('state-loading').style.display = 'none';
  document.getElementById('state-system').style.display = 'none';

  const stateResult = document.getElementById('state-result');
  stateResult.style.display = 'flex';

  document.getElementById('outcome-icon').textContent = config.icon;
  document.getElementById('outcome-label').textContent = config.label;
  document.getElementById('outcome-label').className = 'outcome-label ' + config.theme;
  document.getElementById('outcome-reason').textContent = reason || '';
  document.getElementById('meta-source').textContent = source ? `Source: ${source}` : '';
  document.getElementById('meta-time').textContent = checkedAt
    ? `Checked: ${formatTime(checkedAt)}`
    : '';

  document.getElementById('outcome-card').className = 'outcome-card ' + config.theme;

  // Footer
  document.getElementById('footer-actions').style.display = 'flex';
  const saveBtn = document.getElementById('btn-save-alert');
  saveBtn.style.display = config.showSaveAlert ? 'block' : 'none';
}

function showAlertSaved() {
  const footer = document.getElementById('footer-actions');
  const msg = document.createElement('div');
  msg.className = 'alert-saved';
  msg.textContent = '✓ Alert saved to your CyberShield dashboard';
  footer.appendChild(msg);
  document.getElementById('btn-save-alert').style.display = 'none';
  setTimeout(() => msg.remove(), 3500);
}

function renderPauseState(paused) {
  const btn = document.getElementById('btn-pause');
  const banner = document.getElementById('paused-banner');
  document.getElementById('pause-icon').textContent = paused ? '▶' : '⏸';
  btn.classList.toggle('paused', !!paused);
  btn.title = paused ? 'Resume protection' : 'Pause protection';
  banner.style.display = paused ? 'block' : 'none';
}

function formatTime(isoString) {
  try {
    const d = new Date(isoString);
    const diff = Math.floor((Date.now() - d.getTime()) / 1000);
    if (diff < 5) return 'just now';
    if (diff < 60) return `${diff}s ago`;
    if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
    return d.toLocaleTimeString();
  } catch (_) { return ''; }
}

// ── Message helper ────────────────────────────────────────────────────────────
function sendMsg(msg) {
  return new Promise((resolve) => {
    try {
      chrome.runtime.sendMessage(msg, (response) => {
        if (chrome.runtime.lastError) resolve(null);
        else resolve(response);
      });
    } catch (_) { resolve(null); }
  });
}
