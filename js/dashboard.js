/**
 * CyberShield AI — Dashboard Logic
 * Fetches real scan statistics from the API and renders dashboard.
 */

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
        totalScans: histData.count || scans.length,
        threatsDetected: scans.filter(s => ['Phishing','High Risk','Critical'].includes(s.status)).length,
        safeScans: scans.filter(s => s.status === 'Safe').length,
        avgSecurityScore: Math.round(scans.reduce((a,b) => a + (b.riskScore ? 100 - b.riskScore : 80), 0) / scans.length),
        scansByType: {}
      };
      computed.blocked = computed.threatsDetected;
      updateStatCards(computed);
      return computed;
    }
  } catch (e) {}

  // Demo mode fallback
  showDemoBadge();
  const demo = { totalScans: 1482, threatsDetected: 318, blocked: 318, safeScans: 940, avgSecurityScore: 88, monitored: 12 };
  updateStatCards(demo);
  return demo;
}

function updateStatCards(stats) {
  const set = (id, val) => { const el = document.getElementById(id); if(el) el.textContent = val; };
  set('stat-total-scans', (stats.totalScans || 0).toLocaleString());
  set('stat-threats', (stats.threatsDetected || 0).toLocaleString());
  set('stat-blocked', (stats.blocked || stats.threatsDetected || 0).toLocaleString());
  set('stat-safe', (stats.safeScans || 0).toLocaleString());
  set('stat-monitored', (stats.monitored || 'N/A'));
  set('stat-score', (stats.avgSecurityScore || '--') + '/100');
}

function showDemoBadge() {
  const badge = document.createElement('div');
  badge.className = 'demo-mode-badge';
  badge.innerHTML = '<i class="fas fa-flask"></i> DEMO DATA — Connect MongoDB for live stats';
  document.querySelector('.content-body')?.prepend(badge);
}

async function loadRecentEvents() {
  const feed = document.getElementById('events-feed');
  if (!feed) return;
  
  try {
    const data = await apiRequest('/scan/history');
    if (data.success && data.data.length > 0) {
      feed.innerHTML = '';
      data.data.slice(0, 8).forEach(scan => {
        const time = new Date(scan.createdAt).toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'});
        const isThreat = ['Phishing','High Risk','Critical'].includes(scan.status);
        const dot = isThreat ? 'red' : scan.status === 'Safe' ? 'green' : 'amber';
        const item = document.createElement('div');
        item.className = 'event-item';
        item.style.marginBottom = '12px';
        item.innerHTML = `
          <span class="event-dot ${dot}" style="display:inline-block;width:10px;height:10px;border-radius:50%;background-color:var(--neon-${dot});margin-right:8px;"></span>
          <span class="event-time" style="color:var(--text-muted);font-size:12px;margin-right:12px;">${time}</span>
          <span class="event-text" style="font-size:14px;">${scan.scanType.replace('_',' ')} — <strong>${scan.target.substring(0,25)}${scan.target.length > 25 ? '...' : ''}</strong></span>
          <span class="badge badge-${isThreat ? 'danger' : scan.status === 'Safe' ? 'safe' : 'warning'}" style="float:right;font-size:11px;">${scan.status}</span>
        `;
        feed.appendChild(item);
      });
      return;
    }
  } catch(e) {}
  
  feed.innerHTML = '<div class="empty-state"><i class="fas fa-search"></i><p>No scan events yet. <a href="scanner.html">Start your first scan</a></p></div>';
}

document.addEventListener('DOMContentLoaded', async () => {
  const stats = await loadDashboardStats();
  await loadRecentEvents();
  if (typeof initDashboardCharts === 'function') {
    initDashboardCharts(stats);
  }
});
