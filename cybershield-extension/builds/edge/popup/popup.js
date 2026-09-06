/**
 * CyberShield Browser Extension — Production Popup Controller
 * 
 * Works seamlessly across Microsoft Edge and Mozilla Firefox.
 * Uses centralized config, unified bridge, and friendly error handling.
 */

(function () {
  'use strict';

  const config = globalThis.CYBERSHIELD_CONFIG;
  const bridge = globalThis.CyberShieldBridge;
  const errorHandler = globalThis.CyberShieldErrorHandler;

  // Outcome Visual Presets
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
    SAFE: {
      icon: '✅',
      label: 'Safe',
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

  let currentDomain = null;
  let currentResult = null;

  document.addEventListener('DOMContentLoaded', async () => {
    // 1. Initialize Pause Status
    await refreshPauseStatus();

    // 2. Identify Active Tab & Target URL
    let activeTab = null;
    try {
      const tabs = await bridge.tabs.query({ active: true, currentWindow: true });
      if (tabs && tabs.length > 0) {
        activeTab = tabs[0];
      }
    } catch (_) {}

    const url = activeTab?.url || '';

    // Filter internal or non-HTTP pages
    if (!url || !url.startsWith('http')) {
      showSystemPage();
      return;
    }

    try {
      const parsed = new URL(url);
      currentDomain = parsed.hostname.replace(/^www\./, '').toLowerCase();
      const isHttps = parsed.protocol === 'https:';

      document.getElementById('domain-text').textContent = currentDomain;
      document.getElementById('domain-protocol-icon').textContent = isHttps ? '🔒' : '⚠️';
      document.getElementById('domain-protocol-icon').title = isHttps ? 'Secure HTTPS Connection' : 'Insecure HTTP Connection';

      // 3. Query Background Cache
      const cached = await sendRuntimeMessage({ action: 'getResult', domain: currentDomain });
      if (cached && cached.success && cached.result) {
        currentResult = cached.result;
        renderResult(currentResult);
      } else {
        // 4. Perform Live Check
        await performLiveCheck(currentDomain, isHttps);
      }
    } catch (err) {
      renderError(errorHandler.normalizeError(err, 'URL_PARSE'));
    }

    // ── Button Event Listeners ──────────────────────────────────────────────

    // Pause / Resume Toggle
    document.getElementById('btn-pause')?.addEventListener('click', async () => {
      const resp = await sendRuntimeMessage({ action: 'togglePause' });
      renderPauseState(Boolean(resp && resp.protectionPaused));
    });

    // Run Full Deep SOC Scan
    document.getElementById('btn-full-scan')?.addEventListener('click', () => {
      const target = currentDomain
        ? `${config.DASHBOARD_URL}/scanner.html?url=https://${currentDomain}`
        : `${config.DASHBOARD_URL}/scanner.html`;
      bridge.tabs.create({ url: target });
    });

    // Save Threat Alert to CyberShield Notification Center
    document.getElementById('btn-save-alert')?.addEventListener('click', async () => {
      if (!currentResult || !currentDomain) return;
      const btn = document.getElementById('btn-save-alert');
      btn.disabled = true;
      btn.textContent = 'Saving...';

      try {
        const stored = await bridge.storage.get('csAuthToken');
        const token = stored ? stored.csAuthToken : null;

        if (!token) {
          btn.textContent = 'Login Required on Dashboard';
          setTimeout(() => {
            btn.disabled = false;
            btn.textContent = '💾 Save Alert';
          }, 2500);
          return;
        }

        const res = await fetch(`${config.API_BASE_URL}/extension/alert`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`
          },
          body: JSON.stringify({
            domain: currentDomain,
            outcome: currentResult.outcome,
            reason: currentResult.reason,
            source: currentResult.source
          })
        });

        const data = await res.json();
        if (data && data.success) {
          showAlertSavedConfirmation();
        } else {
          btn.textContent = 'Sign-in Required';
          setTimeout(() => {
            btn.disabled = false;
            btn.textContent = '💾 Save Alert';
          }, 2500);
        }
      } catch (err) {
        btn.disabled = false;
        btn.textContent = '💾 Save Alert';
      }
    });

    // Report False Positive
    document.getElementById('btn-report')?.addEventListener('click', async () => {
      if (!currentDomain) return;
      const btn = document.getElementById('btn-report');
      btn.disabled = true;
      btn.textContent = 'Reporting...';

      try {
        await fetch(`${config.API_BASE_URL}/extension/report-false-positive`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            domain: currentDomain,
            outcome: currentResult?.outcome || 'UNKNOWN'
          })
        });

        btn.textContent = '✓ Recorded';
        setTimeout(() => {
          btn.disabled = false;
          btn.textContent = '⚑ Report False Positive';
        }, 3000);
      } catch (_) {
        btn.disabled = false;
        btn.textContent = '⚑ Report False Positive';
      }
    });

    // Recheck Current Site
    document.getElementById('btn-refresh')?.addEventListener('click', async () => {
      if (!currentDomain) return;
      showLoadingState('Rechecking site posture...');
      await sendRuntimeMessage({ action: 'forceCheck', domain: currentDomain });
      const isHttps = document.getElementById('domain-protocol-icon').textContent === '🔒';
      await performLiveCheck(currentDomain, isHttps);
    });
  });

  // ── Core Communication & Rendering ──────────────────────────────────────────

  async function performLiveCheck(domain, isHttps) {
    showLoadingState('Analyzing site safety...');
    hideErrorNotice();

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), config.REQUEST_TIMEOUT_MS);

    try {
      const res = await fetch(`${config.API_BASE_URL}/extension/check`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json'
        },
        body: JSON.stringify({ domain, isHttps }),
        signal: controller.signal
      });

      clearTimeout(timeoutId);

      if (!res.ok) {
        throw res;
      }

      const payload = await res.json();
      if (payload && payload.success && payload.data) {
        currentResult = payload.data;
        renderResult(currentResult);
      } else {
        renderOutcome('CHECK_FAILED', 'Unable to verify site security at this time.', 'CyberShield');
      }
    } catch (err) {
      clearTimeout(timeoutId);
      const normalized = errorHandler.normalizeError(err, 'LIVE_CHECK');
      renderOutcome('CHECK_FAILED', normalized.message, 'CyberShield Service');
      showErrorNotice(normalized.message);
    }
  }

  function renderResult(result) {
    renderOutcome(result.outcome, result.reason, result.source, result.checkedAt);
  }

  function renderOutcome(outcome, reason, source, checkedAt) {
    const preset = OUTCOMES[outcome] || OUTCOMES.CHECK_FAILED;

    document.getElementById('state-loading').style.display = 'none';
    document.getElementById('state-system').style.display = 'none';

    const stateResult = document.getElementById('state-result');
    stateResult.style.display = 'flex';

    document.getElementById('outcome-icon').textContent = preset.icon;
    document.getElementById('outcome-label').textContent = preset.label;
    document.getElementById('outcome-label').className = 'outcome-label ' + preset.theme;
    document.getElementById('outcome-reason').textContent = reason || '';
    document.getElementById('meta-source').textContent = source ? `Source: ${source}` : '';
    document.getElementById('meta-time').textContent = checkedAt ? `Inspected: ${formatRelativeTime(checkedAt)}` : '';

    document.getElementById('outcome-card').className = 'outcome-card ' + preset.theme;

    // Controls
    document.getElementById('footer-actions').style.display = 'flex';
    const saveBtn = document.getElementById('btn-save-alert');
    if (saveBtn) {
      saveBtn.style.display = preset.showSaveAlert ? 'block' : 'none';
    }
  }

  function showLoadingState(message) {
    document.getElementById('state-loading').style.display = 'flex';
    document.getElementById('state-result').style.display = 'none';
    document.getElementById('state-system').style.display = 'none';
    document.getElementById('footer-actions').style.display = 'none';
    document.getElementById('outcome-card').className = 'outcome-card';
    if (message) {
      document.getElementById('loading-text').textContent = message;
    }
  }

  function showSystemPage() {
    document.getElementById('domain-text').textContent = 'Internal Browser Page';
    document.getElementById('domain-protocol-icon').textContent = '🔵';
    document.getElementById('state-loading').style.display = 'none';
    document.getElementById('state-result').style.display = 'none';
    document.getElementById('state-system').style.display = 'flex';
    document.getElementById('outcome-card').className = 'outcome-card neutral';
    document.getElementById('footer-actions').style.display = 'none';
    hideErrorNotice();
  }

  function showErrorNotice(msg) {
    const el = document.getElementById('error-notice');
    if (el) {
      document.getElementById('error-text').textContent = msg;
      el.style.display = 'flex';
    }
  }

  function hideErrorNotice() {
    const el = document.getElementById('error-notice');
    if (el) el.style.display = 'none';
  }

  function showAlertSavedConfirmation() {
    const footer = document.getElementById('footer-actions');
    const msg = document.createElement('div');
    msg.className = 'alert-saved';
    msg.textContent = '✓ Alert saved to CyberShield Notification Center';
    footer.appendChild(msg);
    document.getElementById('btn-save-alert').style.display = 'none';
    setTimeout(() => msg.remove(), 3500);
  }

  async function refreshPauseStatus() {
    const resp = await sendRuntimeMessage({ action: 'getPauseState' });
    renderPauseState(Boolean(resp && resp.protectionPaused));
  }

  function renderPauseState(paused) {
    const btn = document.getElementById('btn-pause');
    const banner = document.getElementById('paused-banner');
    if (!btn || !banner) return;

    document.getElementById('pause-icon').textContent = paused ? '▶' : '⏸';
    btn.classList.toggle('paused', paused);
    btn.title = paused ? 'Resume protection' : 'Pause protection';
    banner.style.display = paused ? 'block' : 'none';
  }

  function formatRelativeTime(isoString) {
    try {
      const then = new Date(isoString).getTime();
      const diff = Math.floor((Date.now() - then) / 1000);
      if (diff < 5) return 'just now';
      if (diff < 60) return `${diff}s ago`;
      if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
      return new Date(isoString).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    } catch (_) {
      return '';
    }
  }

  function sendRuntimeMessage(msg) {
    return new Promise((resolve) => {
      try {
        bridge.raw.runtime.sendMessage(msg, (response) => {
          if (bridge.raw.runtime.lastError) resolve(null);
          else resolve(response);
        });
      } catch (_) {
        resolve(null);
      }
    });
  }
})();
