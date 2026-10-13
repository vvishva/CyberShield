/**
 * CyberShield AI — SOC Command Center Dashboard Controller
 * Connects real backend statistics, interactive drawer panels, 7D/30D/90D charts, and real-time SSE stream.
 */

let dashboardSummaryData = null;
let currentActivityPeriod = '7d';
let currentTrendPeriod = '7d';

const SCAN_TYPE_LABELS = {
  url_phishing:     { label: 'URL Phishing Scan', icon: 'fa-link',          color: 'var(--cyan)' },
  website_security: { label: 'Website Security',  icon: 'fa-globe',         color: 'var(--green)' },
  ip_reputation:    { label: 'IP Reputation',     icon: 'fa-network-wired', color: 'var(--purple)' },
  password_check:   { label: 'Password Check',    icon: 'fa-key',           color: 'var(--amber)' },
  file_hash:        { label: 'File Hash Scan',    icon: 'fa-file-shield',   color: 'var(--red)' }
};

function getStatusBadge(status) {
  const map = {
    'Safe':        'badge-safe',
    'Clean':       'badge-safe',
    'Low Risk':    'badge-info',
    'Medium Risk': 'badge-warning',
    'High Risk':   'badge-danger',
    'Phishing':    'badge-critical',
    'Critical':    'badge-critical',
    'Malicious':   'badge-critical'
  };
  return map[status] || 'badge-info';
}

function getSeverityBadge(sev) {
  const s = (sev || 'LOW').toLowerCase();
  return `<span class="severity-pill ${s}">${s.toUpperCase()}</span>`;
}

function animateCountUp(elementId, targetValue, duration = 800) {
  const el = document.getElementById(elementId);
  if (!el) return;
  const startValue = 0;
  const startTime = performance.now();
  
  function update(currentTime) {
    const elapsed = currentTime - startTime;
    const progress = Math.min(elapsed / duration, 1);
    const current = Math.floor(progress * (targetValue - startValue) + startValue);
    el.textContent = current.toLocaleString();
    if (progress < 1) requestAnimationFrame(update);
    else el.textContent = targetValue.toLocaleString();
  }
  requestAnimationFrame(update);
}

// ── Clock Ticker ────────────────────────────────────────────────────────────
setInterval(() => {
  const clock = document.getElementById('clock-display');
  if (clock) {
    clock.textContent = new Date().toLocaleString('en-US', { 
      year: 'numeric', month: 'short', day: '2-digit', 
      hour: '2-digit', minute: '2-digit', second: '2-digit', 
      hour12: false, timeZoneName: 'short' 
    });
  }
}, 1000);

// ── Admin Role Permission Check ─────────────────────────────────────────────
function checkAdminAccess() {
  const user = getUser();
  const adminNavItem = document.getElementById('admin-nav-item');
  if (adminNavItem) {
    if (user && user.role === 'admin') {
      adminNavItem.style.display = 'block';
    } else {
      adminNavItem.style.display = 'none';
    }
  }
}

// ── Load Comprehensive Dashboard Summary ────────────────────────────────────
async function fetchDashboardData() {
  try {
    const res = await apiRequest('/scan/dashboard-summary');
    if (res.success && res.data) {
      dashboardSummaryData = res.data;
      renderPosture(res.data.posture);
      renderRiskBreakdown(res.data.posture?.riskBreakdown, res.data.posture?.riskScore);
      renderActiveIncidents(res.data.incidents);
      renderAssetHealth(res.data.assetsHealth);
      renderPriorities(res.data.priorities);
      renderHealth(res.data.health);
      renderChanges(res.data.changes);
      renderRecentOperations(res.data.recentOperations);

      // Render Charts
      if (typeof renderScanActivityChart === 'function' && res.data.activity) {
        renderScanActivityChart(res.data.activity[currentActivityPeriod]);
      }
      if (typeof renderScoreTrendChart === 'function' && res.data.trend) {
        renderScoreTrendChart(res.data.trend[currentTrendPeriod]);
      }
      return res.data;
    }
  } catch (e) {
    console.warn('[Dashboard Summary API Notice] Falling back to default data');
  }

  // Fallback if summary endpoint unavailable
  const fallbackData = {
    posture: { overallScore: 100, riskScore: 10, riskLevel: 'Safe', scoreDelta: 0, activeThreats: 0, vulnerabilities: 0, monitoredAssets: 0, safeAssets: 0 },
    incidents: { total: 0, open: 0, critical: 0, list: [] },
    assetsHealth: { total: 0, healthy: 0, warning: 0, critical: 0 },
    priorities: [],
    health: { webSecurity: 100, sslTls: 100, securityHeaders: 100, threatIntelligence: 100, dns: 100, configuration: 100, vulnerabilities: 100 },
    activity: { '7d': { labels: [], total: [], threats: [], safe: [], failed: [] } },
    trend: { '7d': { labels: [], scores: [] } },
    changes: [],
    recentOperations: []
  };

  dashboardSummaryData = fallbackData;
  renderPosture(fallbackData.posture);
  renderPriorities([]);
  renderHealth(fallbackData.health);
  renderChanges([]);
  renderRecentOperations([]);
  return fallbackData;
}

// ── Render Dynamic Risk Score Breakdown ────────────────────────────────────
function renderRiskBreakdown(breakdown, riskScore) {
  if (!breakdown) return;

  const evalLabel = document.getElementById('risk-score-eval-label');
  if (evalLabel) {
    evalLabel.textContent = `Risk Factor: ${riskScore ?? 15}/100`;
  }

  const setFactor = (id, label, pct, icon) => {
    const el = document.getElementById(id);
    if (el) el.innerHTML = `<i class="fas ${icon}"></i> ${label}: <strong>${pct || 0}%</strong>`;
  };

  setFactor('factor-vuln', 'Vulns', breakdown.vulnerabilities, 'fa-bug');
  setFactor('factor-threat', 'Threats', breakdown.threatActivity, 'fa-crosshairs');
  setFactor('factor-surface', 'Attack Surface', breakdown.attackSurface, 'fa-project-diagram');
  setFactor('factor-config', 'Config', breakdown.configuration, 'fa-lock');
  setFactor('factor-mon', 'Monitoring', breakdown.monitoring, 'fa-radar');
}

// ── Render Active Incidents Triage ──────────────────────────────────────────
function renderActiveIncidents(incidents) {
  const container = document.getElementById('active-incidents-list');
  if (!container) return;

  const list = incidents?.list || [];
  if (list.length === 0) {
    container.innerHTML = `
      <div class="empty-state" style="padding:18px 0; text-align:center;">
        <i class="fas fa-shield-check" style="color:var(--green); font-size:24px; margin-bottom:8px;"></i>
        <p style="margin:0; font-size:13px; color:var(--text-secondary);">No open security incidents. All monitored assets contained.</p>
      </div>
    `;
    return;
  }

  container.innerHTML = list.slice(0, 4).map(inc => {
    const sev = inc.severity || 'MEDIUM';
    const statusColor = inc.status === 'New' ? 'var(--cyan)' : inc.status === 'Investigating' ? 'var(--amber)' : inc.status === 'Contained' ? 'var(--purple)' : 'var(--green)';

    return `
      <div style="display:flex; align-items:center; justify-content:space-between; padding:10px 14px; background:rgba(255,255,255,0.02); border:1px solid var(--border-subtle); border-radius:var(--radius-sm); gap:12px; transition:var(--transition);" class="hover-card">
        <div style="display:flex; align-items:center; gap:10px; min-width:0;">
          ${getSeverityBadge(sev)}
          <div style="min-width:0;">
            <div style="display:flex; align-items:center; gap:6px;">
              <strong style="font-size:13px; color:var(--text-primary); white-space:nowrap; overflow:hidden; text-overflow:ellipsis;">${escapeHtml(inc.title)}</strong>
              <span class="badge" style="font-size:10px; color:${statusColor}; border-color:${statusColor}; padding:1px 6px;">${escapeHtml(inc.status)}</span>
            </div>
            <div style="font-size:11.5px; color:var(--text-muted); margin-top:2px;">
              <span><i class="fas fa-server"></i> ${escapeHtml(inc.relatedAsset || 'Core')}</span> • 
              <span>ID: <code style="color:var(--cyan);">${escapeHtml(inc.incidentId)}</code></span>
            </div>
          </div>
        </div>
        <a href="investigation.html?incidentId=${encodeURIComponent(inc.incidentId)}" class="btn btn-secondary btn-sm" style="flex-shrink:0;">
          <i class="fas fa-magnifying-glass"></i> Triage
        </a>
      </div>
    `;
  }).join('');
}

// ── Render Asset Health Telemetry ───────────────────────────────────────────
function renderAssetHealth(assetsHealth) {
  if (!assetsHealth) return;
  const setEl = (id, val) => {
    const el = document.getElementById(id);
    if (el) el.textContent = val || 0;
  };
  setEl('asset-healthy-count', assetsHealth.healthy);
  setEl('asset-warning-count', assetsHealth.warning);
  setEl('asset-critical-count', assetsHealth.critical);
}

// ── Render Security Posture ─────────────────────────────────────────────────
function renderPosture(posture) {
  if (!posture) return;

  const score = posture.overallScore ?? 100;
  const scoreRing = document.getElementById('soc-score-ring');
  if (scoreRing) {
    scoreRing.style.setProperty('--score-pct', `${score}%`);
  }

  animateCountUp('posture-score', score);

  const riskBadge = document.getElementById('posture-risk-badge');
  if (riskBadge) {
    riskBadge.textContent = posture.riskLevel || 'Safe';
    riskBadge.className = 'severity-pill ' + (
      score >= 90 ? 'safe' : score >= 75 ? 'low' : score >= 50 ? 'medium' : score >= 25 ? 'high' : 'critical'
    );
  }

  const deltaEl = document.getElementById('posture-delta');
  if (deltaEl) {
    const delta = posture.scoreDelta || 0;
    if (delta > 0) {
      deltaEl.innerHTML = `<i class="fas fa-arrow-up" style="color:var(--green);"></i> +${delta} pts this period`;
    } else if (delta < 0) {
      deltaEl.innerHTML = `<i class="fas fa-arrow-down" style="color:var(--red);"></i> ${delta} pts this period`;
    } else {
      deltaEl.innerHTML = `<i class="fas fa-minus" style="color:var(--text-muted);"></i> Stable posture`;
    }
  }

  animateCountUp('posture-threats', posture.activeThreats || 0);
  animateCountUp('posture-vulns', posture.vulnerabilities || 0);
  animateCountUp('posture-monitored', posture.monitoredAssets || 0);
  animateCountUp('posture-safe', posture.safeAssets || 0);
}

// ── Render Top Security Priorities ─────────────────────────────────────────
function renderPriorities(priorities) {
  const container = document.getElementById('top-priorities-list');
  if (!container) return;

  if (!priorities || priorities.length === 0) {
    container.innerHTML = `
      <div class="empty-state" style="padding:15px 0; text-align:center;">
        <i class="fas fa-circle-check" style="color:var(--green); font-size:24px; margin-bottom:8px;"></i>
        <p style="margin:0; font-size:13px; color:var(--text-secondary);">No critical security priorities detected.</p>
      </div>
    `;
    return;
  }

  container.innerHTML = priorities.map(item => `
    <div class="priority-item">
      <div style="display:flex; align-items:center; gap:12px; flex:1; min-width:0;">
        ${getSeverityBadge(item.severity)}
        <div style="min-width:0;">
          <div style="font-weight:700; font-size:13px; color:var(--text-primary); white-space:nowrap; overflow:hidden; text-overflow:ellipsis;">
            ${escapeHtml(item.target)}
          </div>
          <div style="font-size:11px; color:var(--text-muted); margin-top:2px; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;">
            ${escapeHtml(item.explanation)}
          </div>
        </div>
      </div>
      <a href="scanner.html?url=${encodeURIComponent(item.target)}" class="btn btn-secondary btn-sm" style="flex-shrink:0;">
        <i class="fas fa-search"></i> Investigate
      </a>
    </div>
  `).join('');
}

// ── Render Security Health Breakdown ───────────────────────────────────────
function renderHealth(health) {
  const container = document.getElementById('health-grid');
  if (!container || !health) return;

  const categories = [
    { key: 'webSecurity',        label: 'Web Security',    link: 'scanner.html' },
    { key: 'sslTls',             label: 'SSL/TLS Audit',   link: 'scanner.html#ssl' },
    { key: 'securityHeaders',    label: 'Headers Check',   link: 'scanner.html#headers' },
    { key: 'threatIntelligence', label: 'Threat Intel',    link: 'threat-intelligence.html' },
    { key: 'dns',                label: 'DNS Security',    link: 'attack-surface.html' },
    { key: 'configuration',      label: 'Configuration',  link: 'scanner.html' },
    { key: 'vulnerabilities',    label: 'Vulnerabilities', link: 'vulnerabilities.html' }
  ];

  container.innerHTML = categories.map(cat => {
    const score = health[cat.key] ?? 90;
    const color = score >= 80 ? 'var(--green)' : score >= 60 ? 'var(--amber)' : 'var(--red)';
    return `
      <div class="health-item" onclick="window.location.href='${cat.link}'">
        <div class="health-header">
          <span>${cat.label}</span>
          <span style="color:${color}; font-weight:700;">${score}%</span>
        </div>
        <div class="health-track">
          <div class="health-progress" style="width:${score}%; background:${color};"></div>
        </div>
      </div>
    `;
  }).join('');
}

// ── Render Security Changes ────────────────────────────────────────────────
function renderChanges(changes) {
  const container = document.getElementById('security-changes-list');
  if (!container) return;

  if (!changes || changes.length === 0) {
    container.innerHTML = `<div class="empty-state" style="padding:15px 0;"><p>No recent security changes detected.</p></div>`;
    return;
  }

  container.innerHTML = changes.map(c => {
    const time = new Date(c.timestamp || Date.now()).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    return `
      <div style="display:flex; justify-content:space-between; align-items:center; padding:8px 12px; background:rgba(255,255,255,0.02); border-radius:6px; border:1px solid var(--border-subtle);">
        <div style="display:flex; align-items:center; gap:8px;">
          ${getSeverityBadge(c.severity)}
          <span style="color:var(--text-primary); font-weight:600;">${escapeHtml(c.target)}</span>
          <span style="color:var(--text-muted); font-size:11px;">— ${escapeHtml(c.change)}</span>
        </div>
        <span style="color:var(--text-muted); font-size:11px; font-family:var(--font-mono);">${time}</span>
      </div>
    `;
  }).join('');
}

// ── Render Interactive Recent Operations Table ─────────────────────────────
function renderRecentOperations(scans) {
  const tbody = document.getElementById('recent-scans-body');
  if (!tbody) return;

  if (!scans || scans.length === 0) {
    tbody.innerHTML = `<tr><td colspan="7" class="empty-state"><i class="fas fa-shield-virus"></i><p>No recent security operations recorded.</p></td></tr>`;
    return;
  }

  tbody.innerHTML = '';
  scans.forEach(scan => {
    const typeInfo = SCAN_TYPE_LABELS[scan.scanType] || { label: scan.scanType, icon: 'fa-shield', color: 'var(--cyan)' };
    const time = new Date(scan.createdAt).toLocaleString('en-US', { month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit' });
    const badgeClass = getStatusBadge(scan.status);
    const riskScore = scan.riskScore || 0;
    const secScore = 100 - riskScore;

    const tr = document.createElement('tr');
    tr.className = 'interactive-row';
    tr.innerHTML = `
      <td><i class="fas ${typeInfo.icon}" style="color:${typeInfo.color}; font-size:14px;"></i></td>
      <td><strong style="color:var(--text-primary); font-size:13px;">${escapeHtml(scan.target)}</strong></td>
      <td><span style="font-size:12px; color:var(--text-secondary);">${typeInfo.label}</span></td>
      <td>
        <div style="display:flex; align-items:center; gap:8px;">
          <div style="flex:1; max-width:60px; height:4px; background:rgba(255,255,255,0.1); border-radius:2px; overflow:hidden;">
            <div style="width:${riskScore}%; height:100%; background:${riskScore >= 50 ? 'var(--red)' : 'var(--green)'}; border-radius:2px;"></div>
          </div>
          <span style="color:${riskScore >= 50 ? 'var(--red)' : 'var(--green)'}; font-weight:700; font-size:12px;">${secScore}/100</span>
        </div>
      </td>
      <td><span class="badge ${badgeClass}">${scan.status}</span></td>
      <td style="color:var(--text-muted); font-size:12px;">${time}</td>
      <td><button class="btn btn-secondary btn-sm" onclick="event.stopPropagation(); openDetailDrawer('${scan._id}')"><i class="fas fa-eye"></i></button></td>
    `;

    tr.addEventListener('click', () => openDetailDrawer(scan._id));
    tbody.appendChild(tr);
  });
}

let activeDrawerScanId = null;

// ── Operation Detail Drawer ─────────────────────────────────────────────────
function openDetailDrawer(scanId) {
  if (!dashboardSummaryData || !dashboardSummaryData.recentOperations) return;
  const scan = dashboardSummaryData.recentOperations.find(s => s._id === scanId);
  if (!scan) return;

  activeDrawerScanId = scanId;
  const backdrop = document.getElementById('drawer-backdrop');
  const drawer = document.getElementById('detail-drawer');
  const targetEl = document.getElementById('drawer-target');
  const timeEl = document.getElementById('drawer-timestamp');
  const bodyEl = document.getElementById('drawer-body');
  const btnInvestigate = document.getElementById('drawer-btn-investigate');

  if (targetEl) targetEl.textContent = scan.target;
  if (timeEl) timeEl.textContent = new Date(scan.createdAt).toLocaleString();
  if (btnInvestigate) btnInvestigate.href = `scanner.html?url=${encodeURIComponent(scan.target)}`;

  if (bodyEl) {
    const riskScore = scan.riskScore || 0;
    const secScore = 100 - riskScore;
    const details = scan.details || {};

    bodyEl.innerHTML = `
      <div class="drawer-section">
        <h4>Overview</h4>
        <div style="display:flex; justify-content:space-between; align-items:center;">
          <div>
            <div style="font-size:24px; font-weight:800; color:var(--text-primary);">${secScore}/100</div>
            <div style="font-size:11px; color:var(--text-muted);">Security Score</div>
          </div>
          <span class="badge ${getStatusBadge(scan.status)}">${scan.status}</span>
        </div>
      </div>

      <div class="drawer-section">
        <h4>Technical Checks</h4>
        <div style="display:flex; flex-direction:column; gap:8px; font-size:12px;">
          <div style="display:flex; justify-content:space-between;">
            <span style="color:var(--text-muted);">SSL Encryption:</span>
            <span style="color:${details.hasHttps ? 'var(--green)' : 'var(--red)'}; font-weight:600;">
              ${details.hasHttps ? '✓ Enabled' : '✗ Missing / Insecure'}
            </span>
          </div>
          <div style="display:flex; justify-content:space-between;">
            <span style="color:var(--text-muted);">Security Headers:</span>
            <span style="color:var(--text-primary); font-weight:600;">
              ${details.missingHeaders ? `${6 - details.missingHeaders.length}/6 Present` : 'Standard'}
            </span>
          </div>
          <div style="display:flex; justify-content:space-between;">
            <span style="color:var(--text-muted);">Resolved Domain IP:</span>
            <span style="color:var(--cyan); font-family:var(--font-mono);">${details.resolvedIp || 'N/A'}</span>
          </div>
        </div>
      </div>

      ${scan.recommendations && scan.recommendations.length ? `
        <div class="drawer-section">
          <h4>AI Security Recommendations</h4>
          <ul style="margin:0; padding-left:18px; font-size:12px; color:var(--text-secondary); display:flex; flex-direction:column; gap:6px;">
            ${scan.recommendations.map(r => `<li>${escapeHtml(r)}</li>`).join('')}
          </ul>
        </div>
      ` : ''}
    `;
  }

  backdrop.classList.add('active');
  drawer.classList.add('active');
}

function closeDetailDrawer() {
  const backdrop = document.getElementById('drawer-backdrop');
  const drawer = document.getElementById('detail-drawer');
  if (backdrop) backdrop.classList.remove('active');
  if (drawer) drawer.classList.remove('active');
}

// ── SSE Live Feed Listener ──────────────────────────────────────────────────
function connectLiveFeed() {
  const feed = document.getElementById('live-feed');
  const statusPill = document.getElementById('sse-status');
  if (!feed) return;

  const token = typeof getToken === 'function' ? getToken() : null;
  const feedUrl = token ? `/api/events/feed?token=${encodeURIComponent(token)}` : '/api/events/feed';
  const es = new EventSource(feedUrl);

  es.onopen = () => {
    if (statusPill) {
      statusPill.innerHTML = '<span class="pulse-dot"></span> Live SOC Feed';
      statusPill.style.color = 'var(--green)';
    }
  };

  es.onerror = () => {
    if (statusPill) {
      statusPill.innerHTML = '<i class="fas fa-signal"></i> Live Feed Offline';
      statusPill.style.color = 'var(--text-muted)';
    }
  };

  es.onmessage = (event) => {
    try {
      const data = JSON.parse(event.data);
      if (data.type === 'connected') return;

      const empty = feed.querySelector('.empty-state');
      if (empty) empty.remove();

      const time = new Date(data.timestamp || Date.now()).toLocaleTimeString([], { hour12: false });
      let color = 'var(--cyan)', msg = '';

      if (data.type === 'scan_complete') {
        const target = data.target || 'Target';
        const status = data.status || 'Complete';
        if (['Safe','Clean'].includes(status)) color = 'var(--green)';
        else if (['Phishing','Critical','High Risk'].includes(status)) color = 'var(--red)';
        else color = 'var(--amber)';
        msg = `<strong>${escapeHtml(target)}</strong> scanned — Verdict: <span style="color:${color}; font-weight:700;">${status}</span>`;
      } else if (data.type === 'anonymous_network_risk') {
        const netType = data.networkType || 'Network';
        const ip = data.ip || 'Unknown IP';
        const level = data.riskLevel || 'Low';
        if (level === 'Critical' || level === 'High') color = 'var(--red)';
        else if (level === 'Medium') color = 'var(--amber)';
        else color = 'var(--green)';
        msg = `<strong>${escapeHtml(netType)} Session</strong> from <code>${escapeHtml(ip)}</code> — Risk: <span style="color:${color}; font-weight:700;">${level} (${data.riskScore}/100)</span>`;
        if (typeof fetchNetworkRiskData === 'function') {
          fetchNetworkRiskData();
        }
      } else {
        msg = `Event: ${escapeHtml(data.type || 'Activity')}`;
      }

      const item = document.createElement('div');
      item.style.cssText = 'display:flex; align-items:flex-start; gap:10px; padding:6px 10px; background:rgba(255,255,255,0.02); border-radius:6px; border:1px solid var(--border-subtle);';
      item.innerHTML = `
        <span style="width:8px; height:8px; border-radius:50%; background:${color}; margin-top:4px; flex-shrink:0;"></span>
        <div style="flex:1;">
          <div>${msg}</div>
          <div style="font-size:10px; color:var(--text-muted); font-family:var(--font-mono);">${time}</div>
        </div>
      `;

      feed.prepend(item);
      if (feed.children.length > 30) feed.lastElementChild.remove();
      
      // Refresh dashboard
      fetchDashboardData();
    } catch(e) {}
  };
}

// ── Chart Period Switchers Binder ───────────────────────────────────────────
function initPeriodSwitchers() {
  const actSwitcher = document.getElementById('activity-period-switcher');
  if (actSwitcher) {
    actSwitcher.querySelectorAll('.period-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        actSwitcher.querySelectorAll('.period-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        currentActivityPeriod = btn.dataset.period;
        if (dashboardSummaryData && dashboardSummaryData.activity) {
          renderScanActivityChart(dashboardSummaryData.activity[currentActivityPeriod]);
        }
      });
    });
  }

  const trendSwitcher = document.getElementById('trend-period-switcher');
  if (trendSwitcher) {
    trendSwitcher.querySelectorAll('.period-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        trendSwitcher.querySelectorAll('.period-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        currentTrendPeriod = btn.dataset.period;
        if (dashboardSummaryData && dashboardSummaryData.trend) {
          renderScoreTrendChart(dashboardSummaryData.trend[currentTrendPeriod]);
        }
      });
    });
  }
}

// ── AI SOC Security Briefing (Dashboard Only) ──────────────────────────────
async function loadDashboardAIBriefing() {
  const target = document.getElementById('ai-briefing-text');
  if (!target) return;

  target.innerHTML = '<div class="ai-inline-loading"><i class="fas fa-spinner fa-spin"></i> Analyzing live CyberShield SOC telemetry...</div>';

  try {
    const data = await apiRequest('/ai/briefing', 'GET');
    if (data.success && data.data?.briefing) {
      if (typeof window.formatMarkdownResponse === 'function') {
        target.innerHTML = window.formatMarkdownResponse(data.data.briefing);
      } else {
        target.innerHTML = formatBriefingMarkdown(data.data.briefing);
      }
    } else {
      target.innerHTML = '<p class="text-muted">AI Briefing telemetry loaded. Click <strong>AI Security Copilot</strong> for full breakdown.</p>';
    }
  } catch (e) {
    target.innerHTML = '<p class="text-muted"><i class="fas fa-shield-halved text-cyan"></i> AI Shield Active. All endpoints monitored continuously.</p>';
  }
}

function formatBriefingMarkdown(text) {
  if (!text) return '';
  let html = escapeHtml(text);
  html = html.replace(/### (.*?)\n/g, '<h4 class="ai-res-h3">$1</h4>');
  html = html.replace(/## (.*?)\n/g, '<h3 class="ai-res-h2">$1</h3>');
  html = html.replace(/# (.*?)\n/g, '<h2 class="ai-res-h1">$1</h2>');
  html = html.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');
  html = html.replace(/`([^`]+)`/g, '<code>$1</code>');
  html = html.replace(/^- (.*?)$/gm, '<li>$1</li>');
  html = html.replace(/(<li>.*?<\/li>)/gs, '<ul>$1</ul>');
  html = html.replace(/SECURITY SCORE:\s*`?(\d+\/\d+)`?/gi, '<div class="ai-score-pill"><i class="fas fa-shield-cat"></i> SECURITY SCORE: <strong>$1</strong></div>');
  html = html.replace(/Risk Level:\s*`?([^`\n]+)`?/gi, '<span class="badge badge-warning">Risk Level: $1</span>');
  html = html.replace(/\n\n/g, '<br><br>');
  return html;
}

function initDashboardBriefing() {
  const briefingCard = document.getElementById('dashboard-ai-briefing-card');
  const refreshBtn = document.getElementById('btn-refresh-briefing');
  if (briefingCard && refreshBtn) {
    refreshBtn.addEventListener('click', loadDashboardAIBriefing);
    loadDashboardAIBriefing();
  }
}

// ── Anonymous Network Risk Detection (ANRD) Engine ─────────────────────────
let anrdDebounceTimer = null;

async function fetchNetworkRiskData() {
  await Promise.all([
    fetchNetworkRiskSummary(),
    fetchNetworkRiskEvents()
  ]);
}

async function fetchNetworkRiskSummary() {
  try {
    const res = await apiRequest('/network-risk/summary');
    if (res && res.success && res.data) {
      const d = res.data;
      animateCountUp('stat-anrd-anonymous', d.anonymousSessions || 0);
      animateCountUp('stat-anrd-vpn', d.vpnSessions || 0);
      animateCountUp('stat-anrd-proxy', d.proxySessions || 0);
      animateCountUp('stat-anrd-tor', d.torSessions || 0);
      animateCountUp('stat-anrd-high', d.highRiskSessions || 0);
      animateCountUp('stat-anrd-critical', d.criticalAlerts || 0);
    }
  } catch (err) {
    console.warn('[ANRD Summary] notice:', err.message);
  }
}

async function fetchNetworkRiskEvents() {
  const tbody = document.getElementById('anrd-events-tbody');
  if (!tbody) return;

  const riskFilter = document.getElementById('anrd-filter-risk')?.value || 'all';
  const typeFilter = document.getElementById('anrd-filter-type')?.value || 'all';
  const statusFilter = document.getElementById('anrd-filter-status')?.value || 'all';
  const sortFilter = document.getElementById('anrd-filter-sort')?.value || 'newest';
  const search = document.getElementById('anrd-search-input')?.value || '';

  const params = new URLSearchParams({
    riskLevel: riskFilter,
    networkType: typeFilter,
    status: statusFilter,
    sort: sortFilter,
    search: search.trim(),
    limit: 15
  });

  try {
    const res = await apiRequest(`/network-risk/events?${params.toString()}`);
    if (res && res.success && Array.isArray(res.data)) {
      renderNetworkRiskEvents(res.data);
    } else {
      tbody.innerHTML = `<tr><td colspan="11" class="empty-state" style="padding:24px 0;"><i class="fas fa-shield-halved"></i><p>No anonymous network events matching filters.</p></td></tr>`;
    }
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="11" class="empty-state" style="padding:24px 0; color:var(--text-muted);"><i class="fas fa-circle-exclamation"></i><p>Unable to load anonymous network events.</p></td></tr>`;
  }
}

function renderNetworkRiskEvents(events) {
  const tbody = document.getElementById('anrd-events-tbody');
  if (!tbody) return;

  if (!events || events.length === 0) {
    tbody.innerHTML = `<tr><td colspan="11" class="empty-state" style="padding:24px 0;"><i class="fas fa-circle-check text-safe"></i><p>No suspicious or high-risk anonymous sessions recorded.</p></td></tr>`;
    return;
  }

  tbody.innerHTML = events.map(e => {
    const time = new Date(e.createdAt).toLocaleTimeString([], { hour12: false });
    const date = new Date(e.createdAt).toLocaleDateString([], { month: 'short', day: 'numeric' });

    // Indicators pills
    const pills = [];
    if (e.torDetected) pills.push('<span class="badge" style="background:rgba(168,85,247,0.2); color:#c084fc; border:1px solid rgba(168,85,247,0.4); font-size:10px; padding:2px 6px;">TOR</span>');
    if (e.vpnDetected) pills.push('<span class="badge" style="background:rgba(0,200,150,0.2); color:#4ade80; border:1px solid rgba(0,200,150,0.4); font-size:10px; padding:2px 6px;">VPN</span>');
    if (e.proxyDetected) pills.push('<span class="badge" style="background:rgba(245,158,11,0.2); color:#fbbf24; border:1px solid rgba(245,158,11,0.4); font-size:10px; padding:2px 6px;">PROXY</span>');
    if (e.hostingDetected) pills.push('<span class="badge" style="background:rgba(0,212,255,0.2); color:#38bdf8; border:1px solid rgba(0,212,255,0.4); font-size:10px; padding:2px 6px;">HOSTING</span>');
    if (pills.length === 0) pills.push('<span style="color:var(--text-muted); font-size:11px;">Residential</span>');

    // Risk level styling
    let levelHtml = '';
    if (e.riskLevel === 'Critical') {
      levelHtml = '<span class="severity-pill critical">CRITICAL</span>';
    } else if (e.riskLevel === 'High') {
      levelHtml = '<span class="severity-pill high" style="background:rgba(249,115,22,0.2); color:#fb923c; border-color:rgba(249,115,22,0.4);">HIGH</span>';
    } else if (e.riskLevel === 'Medium') {
      levelHtml = '<span class="severity-pill medium">MEDIUM</span>';
    } else {
      levelHtml = '<span class="severity-pill safe">LOW</span>';
    }

    // Status badge
    const isReviewed = e.status === 'Reviewed';
    const statusHtml = isReviewed
      ? '<span style="color:var(--green); font-size:11px; font-weight:600;"><i class="fas fa-circle-check"></i> Reviewed</span>'
      : '<span style="color:var(--cyan); font-size:11px; font-weight:600;"><i class="fas fa-clock"></i> Active</span>';

    return `
      <tr data-event-id="${e._id}">
        <td style="font-size:11px; color:var(--text-muted); font-family:var(--font-mono); white-space:nowrap;">
          <div>${date}</div>
          <div style="color:var(--text-secondary); font-size:10px;">${time}</div>
        </td>
        <td style="font-weight:600; font-size:12px; color:var(--text-primary); max-width:120px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">
          ${escapeHtml(e.username || 'Anonymous')}
        </td>
        <td style="font-family:var(--font-mono); font-size:12px; color:var(--cyan); white-space:nowrap;">
          ${escapeHtml(e.ipAddress)}
        </td>
        <td style="font-size:12px; font-weight:600; color:var(--text-secondary);">
          ${escapeHtml(e.networkType || 'Unknown')}
        </td>
        <td style="font-size:11.5px; color:var(--text-muted); white-space:nowrap;">
          ${escapeHtml(e.country || 'Unknown')}
        </td>
        <td style="white-space:nowrap;">
          <div style="display:flex; gap:4px; flex-wrap:wrap;">${pills.join(' ')}</div>
        </td>
        <td style="font-weight:800; font-family:var(--font-mono); font-size:12px;">
          ${e.riskScore}/100
        </td>
        <td>${levelHtml}</td>
        <td style="font-size:11.5px; color:var(--text-secondary); max-width:240px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;" title="${escapeHtml(e.explanation)}">
          ${escapeHtml(e.explanation)}
        </td>
        <td style="white-space:nowrap;">${statusHtml}</td>
        <td style="white-space:nowrap;">
          <div style="display:flex; gap:6px;">
            <button class="btn btn-secondary btn-sm btn-anrd-inspect" data-id="${e._id}" style="padding:3px 8px; font-size:11px;" title="Inspect Full Telemetry">
              <i class="fas fa-search"></i>
            </button>
            ${!isReviewed ? `
              <button class="btn btn-primary btn-sm btn-anrd-review" data-id="${e._id}" style="padding:3px 8px; font-size:11px;" title="Mark as Reviewed">
                <i class="fas fa-check"></i>
              </button>
            ` : ''}
          </div>
        </td>
      </tr>
    `;
  }).join('');

  // Wire row action buttons
  tbody.querySelectorAll('.btn-anrd-inspect').forEach(btn => {
    btn.addEventListener('click', (ev) => {
      ev.stopPropagation();
      openNetworkRiskInvestigation(btn.dataset.id);
    });
  });

  tbody.querySelectorAll('.btn-anrd-review').forEach(btn => {
    btn.addEventListener('click', async (ev) => {
      ev.stopPropagation();
      await markNetworkRiskReviewed(btn.dataset.id);
    });
  });
}

async function openNetworkRiskInvestigation(eventId) {
  const backdrop = document.getElementById('anrd-modal-backdrop');
  const container = document.getElementById('anrd-modal-content');
  if (!backdrop || !container) return;

  container.innerHTML = `
    <div style="text-align:center; padding:40px 0;">
      <i class="fas fa-spinner fa-spin text-cyan" style="font-size:28px;"></i>
      <p style="margin-top:12px; color:var(--text-muted); font-size:13px;">Retrieving detailed telemetry & intelligence...</p>
    </div>
  `;
  backdrop.style.display = 'flex';

  try {
    const res = await apiRequest(`/network-risk/events/${eventId}`);
    if (!res || !res.success || !res.data) {
      container.innerHTML = `<div class="empty-state" style="padding:20px 0;"><p>Event not found or failed to load.</p></div>`;
      return;
    }

    const e = res.data;
    const timeFormatted = new Date(e.createdAt).toLocaleString();

    let levelBadge = '';
    if (e.riskLevel === 'Critical') levelBadge = '<span class="severity-pill critical">CRITICAL</span>';
    else if (e.riskLevel === 'High') levelBadge = '<span class="severity-pill high" style="background:rgba(249,115,22,0.2); color:#fb923c; border-color:rgba(249,115,22,0.4);">HIGH</span>';
    else if (e.riskLevel === 'Medium') levelBadge = '<span class="severity-pill medium">MEDIUM</span>';
    else levelBadge = '<span class="severity-pill safe">LOW</span>';

    const signalsList = (e.signals && e.signals.length)
      ? e.signals.map(s => `
        <div style="display:flex; justify-content:space-between; align-items:flex-start; padding:8px 10px; background:rgba(255,255,255,0.02); border:1px solid var(--border-glass); border-radius:4px; margin-bottom:6px;">
          <div>
            <div style="font-weight:600; font-size:12.5px; color:var(--text-primary);">${escapeHtml(s.name)}</div>
            <div style="font-size:11px; color:var(--text-muted);">${escapeHtml(s.detail)}</div>
          </div>
          <span style="font-family:var(--font-mono); font-weight:700; color:var(--cyan); font-size:12px;">+${s.weight}</span>
        </div>
      `).join('')
      : '<div style="font-size:12px; color:var(--text-muted);">Standard network baseline signals only.</div>';

    container.innerHTML = `
      <div style="display:flex; justify-content:space-between; align-items:center; border-bottom:1px solid var(--border-glass); padding-bottom:14px; margin-bottom:18px;">
        <div>
          <h3 style="font-size:18px; font-weight:800; color:var(--text-primary); margin:0;">
            <i class="fas fa-network-wired text-cyan" style="margin-right:8px;"></i> Session Risk Investigation
          </h3>
          <span style="font-size:11px; color:var(--text-muted); font-family:var(--font-mono);">Event ID: ${escapeHtml(e._id)} · ${timeFormatted}</span>
        </div>
        <div style="display:flex; align-items:center; gap:8px;">
          ${levelBadge}
          <span class="badge" style="background:rgba(255,255,255,0.04); border:1px solid var(--border-subtle);">${escapeHtml(e.status)}</span>
        </div>
      </div>

      <!-- Score Summary Banner -->
      <div style="display:flex; align-items:center; justify-content:space-between; padding:14px 18px; background:rgba(0,212,255,0.04); border:1px solid rgba(0,212,255,0.2); border-radius:var(--radius-sm); margin-bottom:18px;">
        <div>
          <div style="font-size:11px; text-transform:uppercase; color:var(--text-muted); font-weight:600;">Composite Risk Score</div>
          <div style="font-size:26px; font-weight:900; color:var(--text-primary); font-family:var(--font-mono); margin-top:2px;">
            ${e.riskScore} <span style="font-size:14px; color:var(--text-muted);">/ 100</span>
          </div>
        </div>
        <div style="text-align:right;">
          <div style="font-size:11px; text-transform:uppercase; color:var(--text-muted); font-weight:600;">Network Topology</div>
          <div style="font-size:15px; font-weight:700; color:var(--cyan); margin-top:2px;">
            ${escapeHtml(e.networkType)}
          </div>
        </div>
      </div>

      <!-- Telemetry Details Grid -->
      <div style="display:grid; grid-template-columns:1fr 1fr; gap:16px; margin-bottom:18px;">
        <div class="glass-card" style="padding:14px;">
          <h4 style="font-size:12px; font-weight:700; text-transform:uppercase; color:var(--text-muted); margin-bottom:10px;">
            <i class="fas fa-globe text-cyan" style="margin-right:6px;"></i> Network Intelligence
          </h4>
          <div style="font-size:12px; display:flex; flex-direction:column; gap:6px;">
            <div><span style="color:var(--text-muted);">Source IP:</span> <strong style="font-family:var(--font-mono); color:var(--cyan);">${escapeHtml(e.ipAddress)}</strong></div>
            <div><span style="color:var(--text-muted);">Country / City:</span> <strong>${escapeHtml(e.country)} (${escapeHtml(e.city || 'N/A')})</strong></div>
            <div><span style="color:var(--text-muted);">ISP / Org:</span> <strong>${escapeHtml(e.isp || 'N/A')}</strong></div>
            <div><span style="color:var(--text-muted);">ASN:</span> <code style="color:var(--text-secondary);">${escapeHtml(e.asn || 'N/A')}</code></div>
            <div><span style="color:var(--text-muted);">Tor Exit:</span> <strong>${e.torDetected ? '⚠️ Yes (Verified)' : 'No'}</strong></div>
            <div><span style="color:var(--text-muted);">VPN Tunnel:</span> <strong>${e.vpnDetected ? 'Yes' : 'No'}</strong></div>
            <div><span style="color:var(--text-muted);">Proxy:</span> <strong>${e.proxyDetected ? 'Yes' : 'No'}</strong></div>
          </div>
        </div>

        <div class="glass-card" style="padding:14px;">
          <h4 style="font-size:12px; font-weight:700; text-transform:uppercase; color:var(--text-muted); margin-bottom:10px;">
            <i class="fas fa-user-shield text-cyan" style="margin-right:6px;"></i> Authentication Telemetry
          </h4>
          <div style="font-size:12px; display:flex; flex-direction:column; gap:6px;">
            <div><span style="color:var(--text-muted);">Account:</span> <strong>${escapeHtml(e.username || 'Anonymous')}</strong></div>
            <div><span style="color:var(--text-muted);">Failed Logins:</span> <strong style="color:${e.failedLoginCount >= 2 ? 'var(--red)' : 'var(--text-primary)'};">${e.failedLoginCount} attempts</strong></div>
            <div><span style="color:var(--text-muted);">Suspicious Flag:</span> <strong>${e.suspiciousActivity ? 'Yes' : 'No'}</strong></div>
            <div><span style="color:var(--text-muted);">Target Endpoint:</span> <code style="font-size:11px;">${escapeHtml(e.endpoint || 'General Traffic')}</code></div>
            <div style="margin-top:4px; font-size:11px; color:var(--text-muted); overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">
              <span>UA:</span> ${escapeHtml(e.userAgent || 'Standard Agent')}
            </div>
          </div>
        </div>
      </div>

      <!-- Contributing Signals Breakdown -->
      <div style="margin-bottom:18px;">
        <h4 style="font-size:12px; font-weight:700; text-transform:uppercase; color:var(--text-muted); margin-bottom:8px;">
          <i class="fas fa-chart-pie text-cyan" style="margin-right:6px;"></i> Contributing Risk Signals
        </h4>
        <div>${signalsList}</div>
      </div>

      <!-- Objective Analysis Box -->
      <div style="padding:12px 14px; background:rgba(0,212,255,0.03); border:1px solid rgba(0,212,255,0.2); border-left:4px solid var(--cyan); border-radius:4px; margin-bottom:14px; font-size:12.5px; line-height:1.5;">
        <div style="font-weight:700; color:var(--cyan); margin-bottom:4px;"><i class="fas fa-circle-info"></i> Objective Security Analysis</div>
        <div>${escapeHtml(e.explanation)}</div>
      </div>

      <!-- Recommended SOC Response Box -->
      <div style="padding:12px 14px; background:rgba(0,200,150,0.03); border:1px solid rgba(0,200,150,0.2); border-left:4px solid var(--green); border-radius:4px; margin-bottom:20px; font-size:12.5px; line-height:1.5;">
        <div style="font-weight:700; color:var(--green); margin-bottom:4px;"><i class="fas fa-shield-halved"></i> Actionable SOC Defense Guidance</div>
        <div>${escapeHtml(e.recommendedAction)}</div>
      </div>

      <!-- Modal Actions -->
      <div style="display:flex; justify-content:space-between; align-items:center; border-top:1px solid var(--border-glass); padding-top:16px;">
        <div style="font-size:11px; color:var(--text-muted);">
          <i class="fas fa-scale-balanced" style="margin-right:4px;"></i> Baseline policy: VPN usage alone is Low Risk.
        </div>
        <div style="display:flex; gap:8px;">
          ${e.status !== 'Reviewed' ? `
            <button class="btn btn-primary btn-sm" id="anrd-modal-btn-review" data-id="${e._id}">
              <i class="fas fa-check"></i> Mark Reviewed
            </button>
          ` : `
            <span style="color:var(--green); font-size:12px; font-weight:600; padding:6px 10px;">
              <i class="fas fa-circle-check"></i> Reviewed by ${escapeHtml(e.reviewedBy || 'Analyst')}
            </span>
          `}
          <button class="btn btn-secondary btn-sm" id="anrd-modal-btn-close">Close</button>
        </div>
      </div>
    `;

    // Bind modal actions
    const closeBtn = document.getElementById('anrd-modal-btn-close');
    if (closeBtn) closeBtn.addEventListener('click', closeNetworkRiskInvestigation);

    const reviewBtn = document.getElementById('anrd-modal-btn-review');
    if (reviewBtn) {
      reviewBtn.addEventListener('click', async () => {
        await markNetworkRiskReviewed(reviewBtn.dataset.id);
        openNetworkRiskInvestigation(reviewBtn.dataset.id);
      });
    }
  } catch (err) {
    container.innerHTML = `<div class="empty-state" style="padding:20px 0;"><p>Error loading event details.</p></div>`;
  }
}

function closeNetworkRiskInvestigation() {
  const backdrop = document.getElementById('anrd-modal-backdrop');
  if (backdrop) backdrop.style.display = 'none';
}

async function markNetworkRiskReviewed(eventId) {
  try {
    const res = await apiRequest(`/network-risk/events/${eventId}/review`, 'PATCH');
    if (res && res.success) {
      if (typeof showToast === 'function') {
        showToast('Event marked as reviewed.', 'success');
      }
      await fetchNetworkRiskData();
    }
  } catch (err) {
    if (typeof showToast === 'function') {
      showToast('Failed to review event.', 'error');
    }
  }
}

function initAnonymousNetworkRisk() {
  const riskSection = document.getElementById('anonymous-risk-section');
  if (!riskSection) return;

  // Filter bindings
  const filters = ['anrd-filter-risk', 'anrd-filter-type', 'anrd-filter-status', 'anrd-filter-sort'];
  filters.forEach(id => {
    const el = document.getElementById(id);
    if (el) el.addEventListener('change', fetchNetworkRiskEvents);
  });

  // Debounced search binding
  const searchInput = document.getElementById('anrd-search-input');
  if (searchInput) {
    searchInput.addEventListener('input', () => {
      clearTimeout(anrdDebounceTimer);
      anrdDebounceTimer = setTimeout(fetchNetworkRiskEvents, 350);
    });
  }

  // Refresh button
  const refreshBtn = document.getElementById('btn-refresh-network-risk');
  if (refreshBtn) {
    refreshBtn.addEventListener('click', fetchNetworkRiskData);
  }

  // Modal close handlers
  const modalClose = document.getElementById('anrd-modal-close');
  if (modalClose) modalClose.addEventListener('click', closeNetworkRiskInvestigation);

  const backdrop = document.getElementById('anrd-modal-backdrop');
  if (backdrop) {
    backdrop.addEventListener('click', (ev) => {
      if (ev.target === backdrop) closeNetworkRiskInvestigation();
    });
  }

  // Initial load
  fetchNetworkRiskData();
}

// ── DOM Content Loaded Initialization ───────────────────────────────────────
document.addEventListener('DOMContentLoaded', async () => {
  requireAuth();
  checkAdminAccess();
  initPeriodSwitchers();
  connectLiveFeed();
  initDashboardBriefing();
  initAnonymousNetworkRisk();

  const backdrop = document.getElementById('drawer-backdrop');
  const closeBtn = document.getElementById('drawer-close');
  if (backdrop) backdrop.addEventListener('click', closeDetailDrawer);
  if (closeBtn) closeBtn.addEventListener('click', closeDetailDrawer);

  const drawerReportBtn = document.getElementById('drawer-btn-report');
  if (drawerReportBtn) {
    drawerReportBtn.addEventListener('click', (e) => {
      e.preventDefault();
      if (activeDrawerScanId) {
        downloadReportPDF({ scanId: activeDrawerScanId }, 'CyberShield_Security_Report.pdf');
      } else {
        downloadReportPDF({}, 'CyberShield_Security_Report.pdf');
      }
    });
  }

  await fetchDashboardData();
});

