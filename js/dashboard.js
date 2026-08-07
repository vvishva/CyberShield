/**
 * CyberShield - Main Dashboard Data Loader & Activity Controller
 */

document.addEventListener('DOMContentLoaded', async () => {
  if (document.getElementById('threatPieChart')) {
    initDashboardCharts();
  }

  // Populate Dashboard Stats
  try {
    const res = await apiRequest('/admin/stats');
    if (res.stats) {
      updateStatCard('stat-scans', res.stats.totalScans);
      updateStatCard('stat-threats', res.stats.threatsDetected);
      updateStatCard('stat-safe', res.stats.safeWebsites);
      updateStatCard('stat-score', `${res.stats.securityScore}%`);
    }
  } catch (e) {
    // Offline values
    updateStatCard('stat-scans', '1,482');
    updateStatCard('stat-threats', '318');
    updateStatCard('stat-safe', '940');
    updateStatCard('stat-score', '88%');
  }

  // Load Recent Activities
  loadRecentActivities();
});

function updateStatCard(id, value) {
  const el = document.getElementById(id);
  if (el) el.textContent = value;
}

async function loadRecentActivities() {
  const listEl = document.getElementById('recent-activities-list');
  if (!listEl) return;

  try {
    const res = await apiRequest('/scan/history');
    const items = res.data || [];
    renderActivityItems(listEl, items);
  } catch (e) {
    renderActivityItems(listEl, [
      { target: 'https://paypal-verify-alert.com', scanType: 'url_phishing', status: 'Phishing', createdAt: new Date() },
      { target: 'https://google.com', scanType: 'website_security', status: 'Safe', createdAt: new Date(Date.now() - 3600000) },
      { target: '185.220.101.5', scanType: 'ip_reputation', status: 'Medium Risk', createdAt: new Date(Date.now() - 7200000) }
    ]);
  }
}

function renderActivityItems(container, items) {
  if (items.length === 0) {
    container.innerHTML = '<p style="color: var(--text-muted);">No recent security activity logged.</p>';
    return;
  }

  container.innerHTML = items.map(item => {
    let badgeClass = 'badge-safe';
    if (item.status === 'Phishing' || item.status === 'High Risk' || item.status === 'Weak') badgeClass = 'badge-danger';
    else if (item.status === 'Suspicious' || item.status === 'Medium Risk') badgeClass = 'badge-warning';

    const typeLabel = (item.scanType || 'scan').replace('_', ' ').toUpperCase();
    const timeStr = new Date(item.createdAt || Date.now()).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

    return `
      <div style="display: flex; align-items: center; justify-content: space-between; padding: 14px 0; border-bottom: 1px solid rgba(255,255,255,0.05);">
        <div style="display: flex; align-items: center; gap: 14px;">
          <div style="width: 38px; height: 38px; border-radius: 50%; background: rgba(0,240,255,0.1); color: var(--neon-cyan); display: flex; align-items: center; justify-content: center;">
            <i class="fas ${item.scanType === 'url_phishing' ? 'fa-link' : item.scanType === 'website_security' ? 'fa-globe' : 'fa-network-wired'}"></i>
          </div>
          <div>
            <div style="font-weight: 600; font-size: 14px;">${item.target}</div>
            <div style="font-size: 12px; color: var(--text-muted);">${typeLabel} • ${timeStr}</div>
          </div>
        </div>
        <span class="badge ${badgeClass}">${item.status}</span>
      </div>
    `;
  }).join('');
}
