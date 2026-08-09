/**
 * CyberShield AI — Dashboard Logic
 * Fetches real scan statistics, renders clickable rows, and connects to SSE live feed.
 */

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
    'Low Risk':    'badge-info',
    'Medium Risk': 'badge-warning',
    'High Risk':   'badge-danger',
    'Phishing':    'badge-critical',
    'Critical':    'badge-critical',
    'Malicious':   'badge-critical',
    'Clean':       'badge-safe'
  };
  return map[status] || 'badge-info';
}

function getRiskColor(score) {
  if (score <= 25) return 'var(--green)';
  if (score <= 50) return 'var(--amber)';
  if (score <= 75) return 'var(--red)';
  return '#ff6b6b';
}

// ── Clock ───────────────────────────────────────────────────────────────────
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

// ── SSE Live Feed ───────────────────────────────────────────────────────────
function connectLiveFeed() {
  const token = localStorage.getItem('cybershield_token') || sessionStorage.getItem('cybershield_token');
  const feed = document.getElementById('live-feed');
  const statusPill = document.getElementById('sse-status');

  if (!feed) return;

  const es = new EventSource('/api/events/feed');
  
  es.onopen = () => {
    if (statusPill) {
      statusPill.innerHTML = '<span class="pulse-dot"></span> Live Feed Active';
      statusPill.style.color = 'var(--green)';
      statusPill.style.borderColor = 'rgba(0, 200, 150, 0.2)';
    }
  };

  es.onerror = () => {
    if (statusPill) {
      statusPill.innerHTML = '<i class="fas fa-exclamation-triangle"></i> Feed Reconnecting...';
      statusPill.style.color = 'var(--amber)';
      statusPill.style.borderColor = 'rgba(245, 158, 11, 0.2)';
    }
  };

  es.onmessage = (event) => {
    try {
      const data = JSON.parse(event.data);
      if (data.type === 'connected') return;

      const empty = feed.querySelector('.empty-state');
      if (empty) empty.remove();

      const item = document.createElement('div');
      item.className = 'activity-item';
      
      const time = new Date(data.timestamp || Date.now()).toLocaleTimeString([], { hour12: false });
      
      let icon = 'fa-info-circle', color = 'var(--cyan)', msg = '';

      if (data.type === 'scan_complete') {
        const target = data.target || data.domain || 'Unknown Target';
        const status = data.status || 'Unknown';
        
        if (['Safe','Clean'].includes(status)) { icon = 'fa-check-circle'; color = 'var(--green)'; }
        else if (['Phishing','Critical','High Risk'].includes(status)) { icon = 'fa-skull-crossbones'; color = 'var(--red)'; }
        else { icon = 'fa-exclamation-triangle'; color = 'var(--amber)'; }

        msg = `<strong>${target}</strong> scanned — Result: <span style="color:${color}">${status}</span>`;
      }

      item.innerHTML = `
        <div class="activity-dot" style="background:${color};"></div>
        <div style="flex:1;">
          <div style="color:var(--text-primary); margin-bottom:2px;">${msg}</div>
          <div style="font-size:11px; color:var(--text-muted); font-family:var(--font-mono);">${time}</div>
        </div>
      `;

      feed.prepend(item);
      
      // limit to 50 items
      if (feed.children.length > 50) feed.lastElementChild.remove();
      
      // refresh stats
      loadDashboardStats();

    } catch(e) { console.error('SSE Error:', e); }
  };
}

// ── Stat Cards ──────────────────────────────────────────────────────────────
async function loadDashboardStats() {
  try {
    const data = await apiRequest('/scan/stats');
    if (data.success) {
      updateStatCards(data.data);
      return data.data;
    }
  } catch (e) {}

  // Fallback
  try {
    const histData = await apiRequest('/scan/history');
    if (histData.success && histData.data.length > 0) {
      const scans = histData.data;
      const computed = {
        totalScans:       histData.count || scans.length,
        threatsDetected:  scans.filter(s => ['Phishing','High Risk','Critical','Malicious'].includes(s.status)).length,
        safeScans:        scans.filter(s => ['Safe','Clean'].includes(s.status)).length,
        avgSecurityScore: Math.round(scans.reduce((a,b) => a + (100 - (b.riskScore || 0)), 0) / scans.length),
        monitored:        0,
        vulns:            scans.reduce((a,b) => a + ((b.details && b.details.vulnerabilities) ? b.details.vulnerabilities.length : 0), 0)
      };
      
      try {
        const mon = await apiRequest('/monitor');
        if (mon.success) computed.monitored = mon.data.length;
      } catch(e) {}

      updateStatCards(computed);
      return computed;
    }
  } catch (e) {}

  updateStatCards({ totalScans:0, threatsDetected:0, safeScans:0, avgSecurityScore:0, monitored:0, vulns:0 });
}

function updateStatCards(stats) {
  const set = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = val; };
  set('stat-total-scans', (stats.totalScans  || 0).toLocaleString());
  set('stat-threats',     (stats.threatsDetected || 0).toLocaleString());
  set('stat-vulns',       (stats.vulns || 0).toLocaleString());
  set('stat-safe',        (stats.safeScans || 0).toLocaleString());
  set('stat-monitored',   (stats.monitored || 0).toLocaleString());
  set('stat-score',       (stats.avgSecurityScore || '0') + '/100');
}

// ── Recent Scans Table ──────────────────────────────────────────────────────
async function loadRecentScans() {
  const tbody = document.getElementById('recent-scans-body');
  if (!tbody) return;

  try {
    const data = await apiRequest('/scan/history');
    if (data.success && data.data && data.data.length > 0) {
      const scans = data.data.slice(0, 10); // top 10 for dashboard
      tbody.innerHTML = '';
      
      scans.forEach((scan, idx) => {
        const typeInfo = SCAN_TYPE_LABELS[scan.scanType] || { label: scan.scanType, icon: 'fa-shield', color: 'var(--cyan)' };
        const time = new Date(scan.createdAt).toLocaleString('en-US', { month:'short', day:'2-digit', hour:'2-digit', minute:'2-digit' });
        const badgeClass = getStatusBadge(scan.status);
        const riskColor = getRiskColor(scan.riskScore || 0);

        const tr = document.createElement('tr');
        tr.innerHTML = `
          <td><i class="fas ${typeInfo.icon}" style="color:${typeInfo.color}; opacity:0.8;"></i></td>
          <td><strong style="color:var(--text-primary); font-size:13px;">${scan.target.length > 35 ? scan.target.substring(0,35) + '...' : scan.target}</strong></td>
          <td><span style="font-size:12px; color:var(--text-secondary);">${typeInfo.label}</span></td>
          <td>
            <div style="display:flex; align-items:center; gap:8px;">
              <div style="flex:1; max-width:60px; height:4px; background:rgba(255,255,255,0.1); border-radius:2px; overflow:hidden;">
                <div style="width:${scan.riskScore || 0}%; height:100%; background:${riskColor}; border-radius:2px;"></div>
              </div>
              <span style="color:${riskColor}; font-weight:700; font-size:12px;">${scan.riskScore || 0}%</span>
            </div>
          </td>
          <td><span class="badge ${badgeClass}">${scan.status}</span></td>
          <td style="color:var(--text-muted); font-size:12px;">${time}</td>
          <td><a href="scanner.html?url=${encodeURIComponent(scan.target)}" class="btn btn-secondary btn-sm"><i class="fas fa-redo"></i></a></td>
        `;
        tbody.appendChild(tr);
      });
      return;
    }
  } catch (e) { console.error('Error loading scans:', e); }

  tbody.innerHTML = `<tr><td colspan="7" class="empty-state"><i class="fas fa-shield-virus"></i><p>No operations recorded.</p></td></tr>`;
}

// ── Init ─────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', async () => {
  requireAuth();
  connectLiveFeed();
  const stats = await loadDashboardStats();
  await loadRecentScans();
  
  if (typeof initDashboardCharts === 'function' && stats) {
    try { initDashboardCharts(stats); } catch(e) {}
  }
});
