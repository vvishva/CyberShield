/**
 * CyberShield AI — Automated Security Monitoring Logic
 */

let monitoredData = null;
let currentPeriod = '7d';
let assetToRemove = null;
let monChartInstance = null;

document.addEventListener('DOMContentLoaded', () => {
  requireAuth();
  initMonitoringPage();

  const addForm = document.getElementById('add-monitor-form');
  if (addForm) addForm.addEventListener('submit', handleAddAsset);

  const refreshBtn = document.getElementById('btn-refresh-mon');
  if (refreshBtn) refreshBtn.addEventListener('click', loadMonitoredData);

  const trendSwitcher = document.getElementById('mon-trend-switcher');
  if (trendSwitcher) {
    trendSwitcher.querySelectorAll('.period-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        trendSwitcher.querySelectorAll('.period-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        currentPeriod = btn.dataset.period;
        if (monitoredData && monitoredData.trend) {
          renderScoreChart(monitoredData.trend[currentPeriod]);
        }
      });
    });
  }

  // Modal Cancel & Backdrop click
  const cancelBtn = document.getElementById('btn-cancel-remove');
  const backdrop = document.getElementById('remove-modal-backdrop');
  if (cancelBtn) cancelBtn.addEventListener('click', closeRemoveModal);
  if (backdrop) backdrop.addEventListener('click', closeRemoveModal);

  const confirmBtn = document.getElementById('btn-confirm-remove');
  if (confirmBtn) confirmBtn.addEventListener('click', confirmRemoveAsset);
});

async function initMonitoringPage() {
  await loadMonitoredData();
}

async function loadMonitoredData() {
  try {
    const res = await apiRequest('/scan/monitored');
    if (res.success && res.data) {
      monitoredData = res.data;
      renderMonitoringDashboard(monitoredData);
    }
  } catch (err) {
    console.error('[Monitoring Error]', err);
    showToast('Unable to load monitoring telemetry: ' + err.message, 'warning');
  }
}

function renderMonitoringDashboard(data) {
  const stats = data.stats || {};
  const assets = data.assets || [];

  // Update Stats Cards
  setStat('mon-stat-total', stats.totalAssets || 0);
  setStat('mon-stat-active', stats.activeMonitors || 0);
  setStat('mon-stat-issues', stats.issuesCount || 0);
  const nextScanEl = document.getElementById('mon-stat-next');
  if (nextScanEl) nextScanEl.textContent = stats.nextScanMinutes || '30 min';

  // Render Assets Table or Empty State
  renderAssetsTable(assets);

  // Render Score History Chart
  if (data.trend) {
    renderScoreChart(data.trend[currentPeriod]);
  }

  // Render Changes Feed
  renderChangesFeed(data.changes || []);

  // Render Alerts Feed
  renderAlertsFeed(data.alerts || []);

  // Render Timeline Feed
  renderTimelineFeed(assets);
}

function setStat(id, val) {
  const el = document.getElementById(id);
  if (!el) return;
  const num = parseInt(val) || 0;
  let start = 0;
  const duration = 600;
  const startTime = performance.now();

  function update(now) {
    const elapsed = now - startTime;
    const progress = Math.min(elapsed / duration, 1);
    el.textContent = Math.floor(start + (num - start) * progress).toLocaleString();
    if (progress < 1) requestAnimationFrame(update);
  }
  requestAnimationFrame(update);
}

function renderAssetsTable(assets) {
  const tbody = document.getElementById('monitored-table-body');
  if (!tbody) return;

  if (!assets || assets.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="8" style="padding: 40px 20px; text-align: center;">
          <div style="display:flex; flex-direction:column; align-items:center; gap:12px;">
            <div style="width:60px; height:60px; border-radius:50%; background:var(--cyan-dim); color:var(--cyan); display:flex; align-items:center; justify-content:center; font-size:24px;">
              <i class="fas fa-globe"></i>
            </div>
            <h3 style="font-size:18px; font-weight:700; margin:0; color:var(--text-primary);">No Assets Monitored</h3>
            <p style="color:var(--text-muted); font-size:13px; max-width:400px; margin:0; line-height:1.6;">
              Add your first authorized website to start continuous security monitoring.
            </p>
            <div style="margin-top:8px; text-align:left; background:rgba(0,0,0,0.2); border:1px solid var(--border-subtle); padding:16px; border-radius:var(--radius-md); font-size:12px; color:var(--text-secondary); line-height:1.8;">
              <strong style="color:var(--cyan);">CyberShield will automatically check:</strong><br>
              ✓ SSL/TLS Encryption & Certificate Validity<br>
              ✓ HTTP Security Headers Compliance<br>
              ✓ Security Posture Score & Risk Deltas<br>
              ✓ Security Changes & Real-time Alerts
            </div>
          </div>
        </td>
      </tr>
    `;
    return;
  }

  tbody.innerHTML = assets.map(asset => {
    const statusPill = getStatusPill(asset.status);
    const scoreColor = asset.securityScore >= 75 ? 'var(--green)' : (asset.securityScore >= 50 ? 'var(--amber)' : 'var(--red)');
    const lastScanTime = asset.lastScan ? formatTimeAgo(new Date(asset.lastScan)) : 'Just now';
    const nextScanTime = asset.status === 'Paused' ? 'Paused' : formatNextScan(new Date(asset.nextScan));
    
    let changeTag = '<span style="color:var(--text-muted);">No change</span>';
    if (asset.scoreChange > 0) {
      changeTag = `<span style="color:var(--green); font-weight:700;"><i class="fas fa-arrow-up"></i> +${asset.scoreChange}</span>`;
    } else if (asset.scoreChange < 0) {
      changeTag = `<span style="color:var(--red); font-weight:700;"><i class="fas fa-arrow-down"></i> ${asset.scoreChange}</span>`;
    }

    return `
      <tr>
        <td>
          <div style="display:flex; flex-direction:column;">
            <strong style="color:var(--text-primary); font-size:13px; word-break:break-all;">${escapeHtml(asset.domain)}</strong>
            <span style="font-size:11px; color:var(--text-muted);">${escapeHtml(asset.url)}</span>
          </div>
        </td>
        <td>${statusPill}</td>
        <td>
          <div style="display:flex; align-items:center; gap:8px;">
            <div style="flex:1; max-width:60px; height:5px; background:rgba(255,255,255,0.1); border-radius:3px; overflow:hidden;">
              <div style="width:${asset.securityScore}%; height:100%; background:${scoreColor}; border-radius:3px;"></div>
            </div>
            <span style="font-weight:800; font-size:12px; color:${scoreColor};">${asset.securityScore}/100</span>
          </div>
        </td>
        <td style="font-size:12px; color:var(--text-muted);">${lastScanTime}</td>
        <td style="font-size:12px; color:var(--text-muted);">${nextScanTime}</td>
        <td style="font-size:12px;">${changeTag}</td>
        <td style="font-size:12px; color:var(--text-secondary);">${asset.intervalLabel || asset.interval + ' min'}</td>
        <td>
          <div style="display:flex; gap:6px; flex-wrap:nowrap;">
            <a href="scanner.html?url=${encodeURIComponent(asset.url)}" class="btn btn-secondary btn-sm" title="View Scan"><i class="fas fa-eye"></i></a>
            <button class="btn btn-primary btn-sm" onclick="scanNowAsset('${asset.id}')" title="Scan Now"><i class="fas fa-sync"></i></button>
            <button class="btn btn-secondary btn-sm" onclick="togglePauseAsset('${asset.id}')" title="${asset.status === 'Paused' ? 'Resume' : 'Pause'}">
              <i class="fas ${asset.status === 'Paused' ? 'fa-play text-green' : 'fa-pause text-amber'}"></i>
            </button>
            <button class="btn btn-danger btn-sm" onclick="openRemoveModal('${asset.id}', '${escapeHtml(asset.domain)}')" title="Remove"><i class="fas fa-trash"></i></button>
          </div>
        </td>
      </tr>
    `;
  }).join('');
}

function getStatusPill(status) {
  if (status === 'Healthy') {
    return '<span class="severity-pill" style="background:var(--green-dim); color:var(--green); border:1px solid rgba(0,200,150,0.3);"><i class="fas fa-circle"></i> Healthy</span>';
  } else if (status === 'Warning') {
    return '<span class="severity-pill" style="background:var(--amber-dim); color:var(--amber); border:1px solid rgba(245,158,11,0.3);"><i class="fas fa-circle"></i> Warning</span>';
  } else if (status === 'Critical') {
    return '<span class="severity-pill" style="background:var(--red-dim); color:var(--red); border:1px solid rgba(239,68,68,0.3);"><i class="fas fa-circle"></i> Critical</span>';
  } else {
    return '<span class="severity-pill" style="background:rgba(255,255,255,0.05); color:var(--text-muted); border:1px solid var(--border-subtle);"><i class="fas fa-pause"></i> Paused</span>';
  }
}

function renderScoreChart(trendData) {
  const ctx = document.getElementById('monScoreTrendChart');
  if (!ctx || !trendData) return;

  if (monChartInstance) {
    monChartInstance.destroy();
  }

  monChartInstance = new Chart(ctx, {
    type: 'line',
    data: {
      labels: trendData.labels || ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'],
      datasets: [{
        label: 'Security Score',
        data: trendData.scores || [80, 82, 85, 84, 88, 86, 88],
        borderColor: '#00d4ff',
        backgroundColor: 'rgba(0, 212, 255, 0.08)',
        fill: true,
        tension: 0.35,
        borderWidth: 2,
        pointBackgroundColor: '#00d4ff',
        pointBorderColor: '#0b0f1a',
        pointRadius: 4,
        pointHoverRadius: 6
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false }
      },
      scales: {
        x: { ticks: { color: '#8b95a8', font: { family: 'Inter', size: 11 } }, grid: { display: false } },
        y: { ticks: { color: '#8b95a8', font: { family: 'Inter', size: 11 } }, grid: { color: 'rgba(255,255,255,0.05)' }, min: 0, max: 100 }
      }
    }
  });
}

function renderChangesFeed(changes) {
  const feed = document.getElementById('mon-changes-feed');
  if (!feed) return;

  if (!changes || changes.length === 0) {
    feed.innerHTML = '<div class="empty-state" style="padding:20px 0;"><i class="fas fa-shield-check"></i><p>No security changes recorded.</p></div>';
    return;
  }

  feed.innerHTML = changes.slice(0, 5).map(c => `
    <div style="display:flex; align-items:flex-start; gap:10px; padding:10px 12px; background:rgba(255,255,255,0.02); border:1px solid var(--border-subtle); border-radius:var(--radius-md);">
      <i class="fas ${c.severity === 'CRITICAL' || c.severity === 'HIGH' ? 'fa-arrow-down text-red' : 'fa-circle-check text-green'}" style="margin-top:2px;"></i>
      <div style="flex:1;">
        <div style="display:flex; justify-content:space-between; font-size:12px;">
          <strong style="color:var(--text-primary);">${escapeHtml(c.target)}</strong>
          <span style="color:var(--text-muted); font-size:11px;">${c.time || '10 min ago'}</span>
        </div>
        <div style="font-size:12px; color:var(--text-secondary); margin-top:2px;">${escapeHtml(c.text)}</div>
      </div>
    </div>
  `).join('');
}

function renderAlertsFeed(alerts) {
  const feed = document.getElementById('mon-alerts-feed');
  if (!feed) return;

  if (!alerts || alerts.length === 0) {
    feed.innerHTML = '<div class="empty-state" style="padding:20px 0;"><i class="fas fa-bell-slash"></i><p>No active security alerts.</p></div>';
    return;
  }

  feed.innerHTML = alerts.slice(0, 5).map(a => `
    <div style="display:flex; align-items:center; justify-content:space-between; padding:10px 12px; background:rgba(239,68,68,0.05); border:1px solid rgba(239,68,68,0.2); border-radius:var(--radius-md);">
      <div style="display:flex; align-items:center; gap:10px;">
        <i class="fas fa-bell text-red" style="font-size:14px;"></i>
        <div>
          <div style="font-size:12px; font-weight:700; color:var(--text-primary);">${escapeHtml(a.title)}</div>
          <div style="font-size:11px; color:var(--text-muted);">${escapeHtml(a.target)} • ${a.time}</div>
        </div>
      </div>
      <a href="scanner.html?url=${encodeURIComponent(a.target)}" class="btn btn-secondary btn-sm" style="font-size:11px;">View Alert</a>
    </div>
  `).join('');
}

function renderTimelineFeed(assets) {
  const feed = document.getElementById('mon-timeline-feed');
  if (!feed) return;

  let allTimelineEvents = [];
  assets.forEach(a => {
    if (a.timeline) {
      a.timeline.forEach(t => allTimelineEvents.push({ ...t, domain: a.domain }));
    }
  });

  if (allTimelineEvents.length === 0) {
    feed.innerHTML = '<div class="empty-state" style="padding:20px 0;"><i class="fas fa-clock"></i><p>No timeline events recorded.</p></div>';
    return;
  }

  feed.innerHTML = allTimelineEvents.slice(0, 6).map(t => `
    <div style="display:flex; align-items:flex-start; gap:10px; font-size:12px;">
      <span style="font-family:var(--font-mono); color:var(--text-muted); font-size:11px; width:45px;">${t.time}</span>
      <i class="fas ${t.icon || 'fa-check'}" style="color:${t.type === 'danger' ? 'var(--red)' : (t.type === 'safe' ? 'var(--green)' : 'var(--cyan)')}; margin-top:2px;"></i>
      <span style="color:var(--text-secondary); flex:1;">${escapeHtml(t.text)}</span>
    </div>
  `).join('');
}

async function handleAddAsset(e) {
  e.preventDefault();
  const domainInput = document.getElementById('monitor-domain');
  const intervalSelect = document.getElementById('monitor-interval');
  const btn = document.getElementById('btn-add-monitor');

  const url = domainInput.value.trim();
  if (!url) {
    showToast('Please enter a valid website URL or domain.', 'warning');
    return;
  }

  btn.disabled = true;
  btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Adding Asset...';

  try {
    const res = await apiRequest('/scan/monitored/add', 'POST', {
      url,
      interval: intervalSelect.value
    });

    if (res.success) {
      showToast(`Asset ${res.data.domain} added to continuous monitoring!`, 'success');
      domainInput.value = '';
      await loadMonitoredData();
    }
  } catch (err) {
    showToast(err.message || 'Failed to add asset to monitoring.', 'danger');
  } finally {
    btn.disabled = false;
    btn.innerHTML = '<i class="fas fa-plus"></i> + Start Monitoring';
  }
}

async function scanNowAsset(assetId) {
  try {
    showToast('Triggering immediate security re-scan...', 'info');
    const res = await apiRequest('/scan/monitored/scan-now', 'POST', { assetId });
    if (res.success) {
      showToast(`Re-scan completed for ${res.data.domain}! Security Score: ${res.data.securityScore}/100`, 'success');
      await loadMonitoredData();
    }
  } catch (err) {
    showToast(err.message || 'Re-scan failed.', 'danger');
  }
}

async function togglePauseAsset(assetId) {
  try {
    const res = await apiRequest('/scan/monitored/toggle', 'POST', { assetId });
    if (res.success) {
      showToast(`Monitoring status updated: ${res.data.status}`, 'info');
      await loadMonitoredData();
    }
  } catch (err) {
    showToast(err.message || 'Failed to update asset status.', 'danger');
  }
}

function openRemoveModal(assetId, domain) {
  assetToRemove = assetId;
  const domainEl = document.getElementById('modal-remove-domain');
  const backdrop = document.getElementById('remove-modal-backdrop');
  const modal = document.getElementById('remove-modal');
  
  if (domainEl) domainEl.textContent = domain;
  if (backdrop) backdrop.classList.add('active');
  if (modal) modal.style.display = 'block';
}

function closeRemoveModal() {
  assetToRemove = null;
  const backdrop = document.getElementById('remove-modal-backdrop');
  const modal = document.getElementById('remove-modal');
  if (backdrop) backdrop.classList.remove('active');
  if (modal) modal.style.display = 'none';
}

async function confirmRemoveAsset() {
  if (!assetToRemove) return;
  try {
    const res = await apiRequest('/scan/monitored/remove', 'POST', { assetId: assetToRemove });
    if (res.success) {
      showToast('Asset removed from continuous monitoring.', 'success');
      closeRemoveModal();
      await loadMonitoredData();
    }
  } catch (err) {
    showToast(err.message || 'Failed to remove asset.', 'danger');
  }
}

function formatTimeAgo(date) {
  const seconds = Math.floor((new Date() - date) / 1000);
  if (seconds < 60) return 'Just now';
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes} min ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours} hr ago`;
  return date.toLocaleDateString();
}

function formatNextScan(date) {
  const diffMs = date.getTime() - Date.now();
  if (diffMs <= 0) return 'Scanning now...';
  const minutes = Math.ceil(diffMs / 60000);
  if (minutes < 60) return `in ${minutes} min`;
  const hours = Math.floor(minutes / 60);
  return `in ${hours} hr ${minutes % 60}m`;
}
