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
    posture: { overallScore: 100, riskLevel: 'Safe', scoreDelta: 0, activeThreats: 0, vulnerabilities: 0, monitoredAssets: 0, safeAssets: 0 },
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

  const es = new EventSource('/api/events/feed');

  es.onopen = () => {
    if (statusPill) {
      statusPill.innerHTML = '<span class="pulse-dot"></span> Live SOC Feed';
      statusPill.style.color = 'var(--green)';
    }
  };

  es.onerror = () => {
    if (statusPill) {
      statusPill.innerHTML = '<i class="fas fa-triangle-exclamation"></i> Reconnecting...';
      statusPill.style.color = 'var(--amber)';
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

// ── DOM Content Loaded Initialization ───────────────────────────────────────
document.addEventListener('DOMContentLoaded', async () => {
  requireAuth();
  checkAdminAccess();
  initPeriodSwitchers();
  connectLiveFeed();

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
