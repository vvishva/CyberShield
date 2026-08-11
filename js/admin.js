/**
 * CyberShield AI — Admin Panel Logic
 */

document.addEventListener('DOMContentLoaded', () => {
  requireAuth();
  
  // Basic client-side role check (backend validates for real)
  const userStr = localStorage.getItem('cybershield_user') || sessionStorage.getItem('cybershield_user');
  if (userStr) {
    try {
      const user = JSON.parse(userStr);
      if (user.role === 'admin') {
        document.getElementById('admin-content').style.display = 'block';
        loadAdminData();
      } else {
        document.getElementById('not-admin-state').style.display = 'block';
      }
    } catch(e) {}
  }

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
}
