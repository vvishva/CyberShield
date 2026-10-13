/**
 * CyberShield AI — Admin Panel Logic
 */

document.addEventListener('DOMContentLoaded', () => {
  requireAuth();
  
  const currentUser = getUser();
  if (!currentUser || currentUser.role !== 'admin') {
    showToast('Access Denied: Admin privileges required.', 'danger');
    setTimeout(() => {
      window.location.replace('dashboard.html');
    }, 200);
    return;
  }

  const adminContent = document.getElementById('admin-content');
  if (adminContent) adminContent.style.display = 'block';
  loadAdminData();

  const exportBtn = document.getElementById('btn-export-admin-pdf');
  if (exportBtn) {
    exportBtn.addEventListener('click', (e) => {
      e.preventDefault();
      downloadReportPDF({ type: 'admin_audit' }, 'CyberShield_Admin_Audit_Report.pdf');
    });
  }
});

function logAudit(msg) {
  const logBox = document.getElementById('audit-logs');
  if (!logBox) return;
  const time = new Date().toISOString().substring(11, 19);
  logBox.innerHTML += `[${time}] ${msg}<br>`;
  logBox.scrollTop = logBox.scrollHeight;
}

async function loadAdminData() {
  logAudit('Fetching system users list...');
  
  try {
    // Attempt to load users via API
    const res = await apiRequest('/admin/users');
    
    // Attempt to load total scans
    const statRes = await apiRequest('/scan/stats');
    if (statRes.success && statRes.data) {
      document.getElementById('adm-scans-count').textContent = (statRes.data.totalScans || 0).toLocaleString();
    }
    
    if (res.success && res.data) {
      const users = res.data;
      document.getElementById('adm-users-count').textContent = users.length;
      
      const tbody = document.getElementById('admin-users-body');
      tbody.innerHTML = users.map(u => `
        <tr>
          <td style="font-family:var(--font-mono); font-size:11px; color:var(--text-muted);">${u._id}</td>
          <td><strong style="color:var(--text-primary);">${escapeHtml(u.username)}</strong></td>
          <td>${escapeHtml(u.email)}</td>
          <td>
            <span class="badge ${u.role === 'admin' ? 'badge-purple' : 'badge-info'}">
              ${u.role.toUpperCase()}
            </span>
          </td>
          <td style="font-size:12px; color:var(--text-muted);">
            ${new Date(u.createdAt).toLocaleDateString()}
          </td>
          <td>
            <button class="btn btn-secondary btn-sm" onclick="showToast('Manage user ${u.username}', 'info')">
              <i class="fas fa-cog"></i>
            </button>
            ${u.role !== 'admin' ? `
            <button class="btn btn-danger btn-sm" onclick="showToast('Delete not permitted in demo', 'warning')">
              <i class="fas fa-trash"></i>
            </button>` : ''}
          </td>
        </tr>
      `).join('');
      
      logAudit(`Loaded ${users.length} registered users successfully.`);
    } else {
      throw new Error(res.error || 'Admin API access denied');
    }
  } catch(err) {
    console.error(err);
    if (err.message.includes('403') || err.message.includes('authorized')) {
      document.getElementById('admin-content').style.display = 'none';
      document.getElementById('not-admin-state').style.display = 'block';
    } else {
      document.getElementById('admin-users-body').innerHTML = `
        <tr><td colspan="6" class="error-state"><i class="fas fa-exclamation-triangle"></i> Failed to load user data: ${err.message}</td></tr>
      `;
      logAudit(`<span style="color:var(--red);">[ERROR] ${err.message}</span>`);
    }
  }

  // Load Anonymous Network Risk Detection Configuration
  await loadNetworkRiskConfig();
}

async function loadNetworkRiskConfig() {
  try {
    const res = await apiRequest('/network-risk/config');
    if (res && res.success && res.data) {
      const cfg = res.data;
      const w = cfg.weights || {};

      const enabledEl = document.getElementById('anrd-cfg-enabled');
      if (enabledEl) enabledEl.checked = cfg.enabled !== false;

      const setVal = (id, val) => {
        const el = document.getElementById(id);
        if (el && val !== undefined) el.value = val;
      };

      setVal('anrd-cfg-w-vpn', w.vpn ?? 15);
      setVal('anrd-cfg-w-proxy', w.proxy ?? 15);
      setVal('anrd-cfg-w-tor', w.tor ?? 25);
      setVal('anrd-cfg-w-hosting', w.hosting ?? 15);
      setVal('anrd-cfg-w-failed', w.failedLogins ?? 20);
      setVal('anrd-cfg-w-newsession', w.newSession ?? 10);
      setVal('anrd-cfg-w-suspiciousapi', w.suspiciousApi ?? 20);
      setVal('anrd-cfg-w-sensitive', w.sensitiveEndpoint ?? 15);
      setVal('anrd-cfg-w-ratelimit', w.rateLimitViolation ?? 15);
      setVal('anrd-cfg-alert-threshold', cfg.alertThreshold || 'High');
      setVal('anrd-cfg-cooldown', cfg.cooldownMinutes ?? 5);
      setVal('anrd-cfg-provider', cfg.provider || 'auto');

      logAudit('Anonymous Network Risk Detection configuration loaded.');
    }
  } catch (err) {
    console.warn('[ANRD Admin Config] load error:', err.message);
  }

  const saveBtn = document.getElementById('btn-save-anrd-config');
  if (saveBtn) {
    saveBtn.onclick = async () => {
      saveBtn.disabled = true;
      saveBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Saving...';

      const getNum = (id, d) => {
        const el = document.getElementById(id);
        return el ? parseInt(el.value, 10) || d : d;
      };

      const payload = {
        enabled: document.getElementById('anrd-cfg-enabled')?.checked ?? true,
        weights: {
          vpn: getNum('anrd-cfg-w-vpn', 15),
          proxy: getNum('anrd-cfg-w-proxy', 15),
          tor: getNum('anrd-cfg-w-tor', 25),
          hosting: getNum('anrd-cfg-w-hosting', 15),
          failedLogins: getNum('anrd-cfg-w-failed', 20),
          newSession: getNum('anrd-cfg-w-newsession', 10),
          suspiciousApi: getNum('anrd-cfg-w-suspiciousapi', 20),
          sensitiveEndpoint: getNum('anrd-cfg-w-sensitive', 15),
          rateLimitViolation: getNum('anrd-cfg-w-ratelimit', 15)
        },
        alertThreshold: document.getElementById('anrd-cfg-alert-threshold')?.value || 'High',
        cooldownMinutes: getNum('anrd-cfg-cooldown', 5),
        provider: document.getElementById('anrd-cfg-provider')?.value || 'auto'
      };

      try {
        const res = await apiRequest('/network-risk/config', 'PUT', payload);
        if (res && res.success) {
          showToast('Anonymous Network Risk Settings saved successfully.', 'success');
          logAudit('<span style="color:var(--green);">[CONFIG] Network Risk scoring weights updated successfully.</span>');
        } else {
          showToast(res.error || 'Failed to update settings', 'danger');
        }
      } catch (e) {
        showToast(e.message || 'Error updating settings', 'danger');
      } finally {
        saveBtn.disabled = false;
        saveBtn.innerHTML = '<i class="fas fa-save"></i> Save Risk Settings';
      }
    };
  }
}
