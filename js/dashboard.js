/**
 * CyberShield AI — Dashboard Logic
 * Fetches real scan statistics and renders clickable, detailed scan rows.
 */

const SCAN_TYPE_LABELS = {
  url_phishing:     { label: 'URL Phishing Scan', icon: 'fa-link',          color: 'var(--neon-cyan)' },
  website_security: { label: 'Website Security',  icon: 'fa-globe',         color: 'var(--neon-green)' },
  ip_reputation:    { label: 'IP Reputation',     icon: 'fa-network-wired', color: 'var(--neon-purple)' },
  password_check:   { label: 'Password Check',    icon: 'fa-key',           color: 'var(--neon-amber)' },
  file_hash:        { label: 'File Hash Scan',    icon: 'fa-file-shield',   color: 'var(--neon-red)' }
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
  if (score <= 25) return 'var(--neon-green)';
  if (score <= 50) return 'var(--neon-amber)';
  if (score <= 75) return 'var(--neon-red)';
  return '#ff0000';
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

  // Fallback: compute from history
  try {
    const histData = await apiRequest('/scan/history');
    if (histData.success && histData.data.length > 0) {
      const scans = histData.data;
      const computed = {
        totalScans:       histData.count || scans.length,
        threatsDetected:  scans.filter(s => ['Phishing','High Risk','Critical','Malicious'].includes(s.status)).length,
        safeScans:        scans.filter(s => ['Safe','Clean'].includes(s.status)).length,
        avgSecurityScore: Math.round(scans.reduce((a,b) => a + (100 - (b.riskScore || 0)), 0) / scans.length),
        monitored:        new Set(scans.map(s => { try { return new URL(s.target).hostname; } catch { return s.target; } })).size
      };
      computed.blocked = computed.threatsDetected;
      updateStatCards(computed);
      return computed;
    }
  } catch (e) {}

  // Demo mode
  const demo = { totalScans: 4, threatsDetected: 1, blocked: 1, safeScans: 3, avgSecurityScore: 65, monitored: 3 };
  updateStatCards(demo);
  return demo;
}

function updateStatCards(stats) {
  const set = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = val; };
  set('stat-total-scans', (stats.totalScans  || 0).toLocaleString());
  set('stat-threats',     (stats.threatsDetected || 0).toLocaleString());
  set('stat-blocked',     (stats.blocked || stats.threatsDetected || 0).toLocaleString());
  set('stat-safe',        (stats.safeScans || 0).toLocaleString());
  set('stat-monitored',   (stats.monitored || 0).toLocaleString());
  set('stat-score',       (stats.avgSecurityScore || '--') + '/100');
}

// ── Recent Scans Table (expandable) ─────────────────────────────────────────
async function loadRecentScans() {
  const tbody = document.getElementById('recent-scans-body');
  const badge = document.getElementById('scan-count-badge');
  if (!tbody) return;

  try {
    const data = await apiRequest('/scan/history');
    if (data.success && data.data && data.data.length > 0) {
      const scans = data.data;
      if (badge) badge.textContent = `${scans.length} recent records`;

      tbody.innerHTML = '';
      scans.forEach((scan, idx) => {
        const typeInfo = SCAN_TYPE_LABELS[scan.scanType] || { label: scan.scanType, icon: 'fa-shield', color: 'var(--neon-cyan)' };
        const time = new Date(scan.createdAt).toLocaleString('en-IN', { day:'2-digit', month:'short', hour:'2-digit', minute:'2-digit' });
        const badgeClass = getStatusBadge(scan.status);
        const riskColor = getRiskColor(scan.riskScore || 0);
        const isThreat = ['Phishing','High Risk','Critical','Malicious'].includes(scan.status);

        // Main row
        const tr = document.createElement('tr');
        tr.className = 'scan-row';
        tr.style.borderLeft = isThreat ? '3px solid var(--neon-red)' : '3px solid transparent';
        tr.setAttribute('data-idx', idx);
        tr.innerHTML = `
          <td style="text-align:center; color:var(--text-dim);">
            <i class="fas fa-chevron-right toggle-icon" style="font-size:11px; transition:transform 0.2s;"></i>
          </td>
          <td>
            <div style="display:flex; align-items:center; gap:10px;">
              <i class="fas ${typeInfo.icon}" style="color:${typeInfo.color}; width:18px;"></i>
              <div>
                <strong style="color:#fff; font-size:14px;">${scan.target.length > 45 ? scan.target.substring(0,45) + '...' : scan.target}</strong>
                <div style="font-size:11px; color:var(--text-dim); margin-top:2px;">${scan._id}</div>
              </div>
            </div>
          </td>
          <td>
            <span style="font-size:12px; color:${typeInfo.color}; background:${typeInfo.color}18; padding:3px 10px; border-radius:20px; border:1px solid ${typeInfo.color}33;">
              <i class="fas ${typeInfo.icon}" style="margin-right:5px;"></i>${typeInfo.label}
            </span>
          </td>
          <td>
            <div style="display:flex; align-items:center; gap:8px;">
              <div style="width:60px; height:6px; background:rgba(255,255,255,0.1); border-radius:3px; overflow:hidden;">
                <div style="width:${scan.riskScore || 0}%; height:100%; background:${riskColor}; border-radius:3px;"></div>
              </div>
              <span style="color:${riskColor}; font-weight:700; font-size:14px;">${scan.riskScore || 0}%</span>
            </div>
          </td>
          <td><span class="badge ${badgeClass}">${scan.status}</span></td>
          <td style="color:var(--text-muted); font-size:13px;">${time}</td>
          <td>
            <a href="scanner.html" class="btn btn-secondary" style="padding:4px 12px; font-size:12px;">
              <i class="fas fa-redo"></i> Re-scan
            </a>
          </td>
        `;

        // Detail panel row
        const detailTr = document.createElement('tr');
        detailTr.style.background = 'transparent';
        const details = scan.details || {};
        const recs = (scan.recommendations || []).slice(0, 3);

        detailTr.innerHTML = `
          <td colspan="7" style="padding:0 16px; border:none;">
            <div class="scan-detail-panel" id="detail-${idx}">
              <div class="detail-grid">
                <div class="detail-item">
                  <label>Full Target</label>
                  <span style="word-break:break-all; font-size:13px;">${scan.target}</span>
                </div>
                <div class="detail-item">
                  <label>Risk Score</label>
                  <span style="color:${riskColor};">${scan.riskScore || 0}% Risk</span>
                </div>
                <div class="detail-item">
                  <label>Confidence</label>
                  <span>${scan.confidenceScore || (100 - (scan.riskScore || 0))}%</span>
                </div>
                <div class="detail-item">
                  <label>Verdict</label>
                  <span class="badge ${badgeClass}">${scan.status}</span>
                </div>
                ${details.domain ? `<div class="detail-item"><label>Domain</label><span>${details.domain}</span></div>` : ''}
                ${details.resolvedIp ? `<div class="detail-item"><label>Resolved IP</label><span>${details.resolvedIp}</span></div>` : ''}
                ${details.securityScore !== undefined ? `<div class="detail-item"><label>Security Score</label><span style="color:var(--neon-green);">${details.securityScore}/100</span></div>` : ''}
                ${details.hasHttps !== undefined ? `<div class="detail-item"><label>HTTPS</label><span style="color:${details.hasHttps ? 'var(--neon-green)' : 'var(--neon-red)'}">${details.hasHttps ? '✓ Enabled' : '✗ Missing'}</span></div>` : ''}
              </div>
              ${recs.length > 0 ? `
                <div style="border-top:1px solid rgba(0,240,255,0.1); padding-top:14px; margin-top:4px;">
                  <label style="font-size:11px; text-transform:uppercase; letter-spacing:1px; color:var(--text-dim); display:block; margin-bottom:10px;">Recommendations</label>
                  ${recs.map(r => `<div style="display:flex;align-items:flex-start;gap:8px;margin-bottom:8px;"><i class="fas fa-arrow-right" style="color:var(--neon-cyan);margin-top:2px;font-size:11px;flex-shrink:0;"></i><span style="font-size:13px;">${r}</span></div>`).join('')}
                </div>
              ` : ''}
            </div>
          </td>
        `;

        tbody.appendChild(tr);
        tbody.appendChild(detailTr);

        // Toggle expand on row click
        tr.addEventListener('click', () => {
          const panel = document.getElementById(`detail-${idx}`);
          const icon = tr.querySelector('.toggle-icon');
          const isOpen = panel.classList.toggle('open');
          if (icon) icon.style.transform = isOpen ? 'rotate(90deg)' : 'rotate(0deg)';
        });
      });
      return;
    }
  } catch (e) {
    console.error('Error loading scans:', e);
  }

  // Empty state
  tbody.innerHTML = `
    <tr>
      <td colspan="7" style="text-align:center; padding:48px 20px;">
        <i class="fas fa-shield-virus" style="font-size:48px; color:var(--border-glass); margin-bottom:16px; display:block;"></i>
        <p style="color:var(--text-muted); margin-bottom:16px;">No scans yet. Start your first security scan.</p>
        <a href="scanner.html" class="btn btn-primary"><i class="fas fa-search"></i> Run First Scan</a>
      </td>
    </tr>
  `;
}

// ── Init ─────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', async () => {
  const stats = await loadDashboardStats();
  await loadRecentScans();
  if (typeof initDashboardCharts === 'function') {
    initDashboardCharts(stats);
  }
});
