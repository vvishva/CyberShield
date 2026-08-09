/**
 * CyberShield Auto Monitoring
 */

document.addEventListener('DOMContentLoaded', () => {
  requireAuth(); // Ensure user is logged in
  loadMonitoredSites();

  document.getElementById('add-monitor-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const btn = e.target.querySelector('button');
    const domainInput = document.getElementById('monitor-domain');
    const domain = domainInput.value.trim();
    const interval = document.getElementById('monitor-interval').value;

    if (!domain) {
      showToast('Please enter a domain', 'warning');
      return;
    }

    btn.disabled = true;
    btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Adding...';

    try {
      const res = await apiRequest('/monitor', 'POST', { domain, interval: parseInt(interval) });
      if (res.success) {
        showToast('Domain added to auto-monitoring', 'success');
        domainInput.value = '';
        loadMonitoredSites();
      } else {
        throw new Error(res.error || 'Failed to add domain');
      }
    } catch (err) {
      showToast(err.message, 'danger');
    } finally {
      btn.disabled = false;
      btn.innerHTML = '<i class="fas fa-radar"></i> Start Monitoring';
    }
  });
});

async function loadMonitoredSites() {
  const tbody = document.getElementById('monitor-table-body');
  try {
    const res = await apiRequest('/monitor');
    if (res.success) {
      const sites = res.data;
      updateMonitorStats(sites);
      
      if (sites.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" class="empty-state"><i class="fas fa-radar"></i><p>No sites monitored yet. Add your first domain above.</p></td></tr>';
        return;
      }

      tbody.innerHTML = sites.map(site => `
        <tr>
          <td><strong style="color:var(--text-primary)">${escapeHtml(site.domain)}</strong></td>
          <td>
            ${site.active 
              ? '<span class="badge badge-safe"><i class="fas fa-check"></i> Active</span>'
              : '<span class="badge badge-warning"><i class="fas fa-pause"></i> Paused</span>'}
          </td>
          <td>
            ${site.lastScore !== null 
              ? `<div style="display:flex;align-items:center;gap:8px;">
                   <div style="flex:1;height:4px;background:rgba(255,255,255,.1);border-radius:2px;overflow:hidden;min-width:60px;">
                     <div style="height:100%;width:${site.lastScore}%;background:${getScoreColor(site.lastScore)};border-radius:2px;"></div>
                   </div>
                   <span style="font-weight:700;color:${getScoreColor(site.lastScore)}">${site.lastScore}</span>
                 </div>`
              : '<span class="badge badge-info">Pending Scan</span>'}
          </td>
          <td>${site.lastScan ? formatTimeAgo(site.lastScan) : 'Never'}</td>
          <td>${site.active ? formatTimeAgo(site.nextScan) : '—'}</td>
          <td>Every ${site.interval >= 60 ? site.interval/60 + ' hours' : site.interval + ' min'}</td>
          <td>
            <div style="display:flex;gap:6px;">
              <button onclick="toggleMonitor('${site._id}', ${site.active})" class="btn btn-secondary btn-sm" title="${site.active ? 'Pause' : 'Resume'}">
                <i class="fas fa-${site.active ? 'pause' : 'play'}"></i>
              </button>
              <button onclick="removeMonitor('${site._id}')" class="btn btn-danger btn-sm" title="Remove">
                <i class="fas fa-trash"></i>
              </button>
            </div>
          </td>
        </tr>
      `).join('');
    }
  } catch (err) {
    console.error('Failed to load monitored sites:', err);
    tbody.innerHTML = `<tr><td colspan="7" class="error-state"><i class="fas fa-exclamation-triangle"></i> Error loading monitored sites. ${err.message}</td></tr>`;
  }
}

function updateMonitorStats(sites) {
  document.getElementById('mon-total').textContent = sites.length;
  document.getElementById('mon-active').textContent = sites.filter(s => s.active).length;
  
  const issues = sites.filter(s => s.lastScore !== null && s.lastScore < 75).length;
  document.getElementById('mon-issues').textContent = issues;
  
  let next = '—';
  if (sites.length > 0) {
    const activeSites = sites.filter(s => s.active);
    if (activeSites.length > 0) {
      const nextScanDate = new Date(Math.min(...activeSites.map(s => new Date(s.nextScan))));
      if (nextScanDate <= new Date()) {
        next = 'Now';
      } else {
        const diff = Math.floor((nextScanDate - new Date()) / 60000);
        next = `In ${diff}m`;
      }
    }
  }
  document.getElementById('mon-next').textContent = next;
}

async function toggleMonitor(id, currentActive) {
  try {
    const res = await apiRequest(`/monitor/${id}/toggle`, 'PATCH');
    if (res.success) {
      showToast(`Monitoring ${currentActive ? 'paused' : 'resumed'}`, 'success');
      loadMonitoredSites();
    }
  } catch (err) {
    showToast(err.message, 'danger');
  }
}

async function removeMonitor(id) {
  if (!confirm('Are you sure you want to remove this domain from monitoring?')) return;
  try {
    const res = await apiRequest(`/monitor/${id}`, 'DELETE');
    if (res.success) {
      showToast('Domain removed', 'success');
      loadMonitoredSites();
    }
  } catch (err) {
    showToast(err.message, 'danger');
  }
}

function getScoreColor(score) {
  if (score >= 90) return 'var(--green)';
  if (score >= 75) return 'var(--cyan)';
  if (score >= 50) return 'var(--amber)';
  return 'var(--red)';
}

function formatTimeAgo(dateString) {
  if (!dateString) return '';
  const date = new Date(dateString);
  const now = new Date();
  const diffMs = now - date;
  
  const absDiff = Math.abs(diffMs);
  const diffMins = Math.floor(absDiff / 60000);
  const diffHrs = Math.floor(diffMins / 60);
  const diffDays = Math.floor(diffHrs / 24);
  
  let text = '';
  if (diffMins < 1) text = 'Just now';
  else if (diffMins < 60) text = `${diffMins}m`;
  else if (diffHrs < 24) text = `${diffHrs}h`;
  else text = `${diffDays}d`;
  
  return diffMs < 0 ? `In ${text}` : `${text} ago`;
}
