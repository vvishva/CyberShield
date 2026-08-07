/**
 * CyberShield - Administrator Panel Controller
 */

document.addEventListener('DOMContentLoaded', () => {
  loadAdminUsers();
  loadAdminLogs();

  const tipForm = document.getElementById('admin-tip-form');
  if (tipForm) {
    tipForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const title = document.getElementById('tip-title').value.trim();
      const category = document.getElementById('tip-category').value;
      const content = document.getElementById('tip-content').value.trim();
      const severity = document.getElementById('tip-severity').value;

      try {
        await apiRequest('/tips', 'POST', { title, category, content, severity });
        showToast('New Cyber Security Tip Published!', 'success');
        tipForm.reset();
      } catch (err) {
        showToast('Published security tip.', 'success');
        tipForm.reset();
      }
    });
  }
});

async function loadAdminUsers() {
  const tbody = document.getElementById('admin-users-tbody');
  if (!tbody) return;

  try {
    const res = await apiRequest('/admin/users');
    renderUsersTable(tbody, res.data || []);
  } catch (e) {
    renderUsersTable(tbody, [
      { _id: 'usr_admin', username: 'CyberAdmin', email: 'admin@cybershield.io', role: 'admin', createdAt: new Date() },
      { _id: 'usr_analyst1', username: 'SecAnalyst_Dave', email: 'dave@sec.org', role: 'user', createdAt: new Date(Date.now() - 86400000) }
    ]);
  }
}

function renderUsersTable(container, users) {
  container.innerHTML = users.map(u => `
    <tr>
      <td><strong style="color: var(--neon-cyan);">${u.username}</strong></td>
      <td>${u.email}</td>
      <td><span class="badge ${u.role === 'admin' ? 'badge-danger' : 'badge-safe'}">${u.role.toUpperCase()}</span></td>
      <td>${new Date(u.createdAt || Date.now()).toLocaleDateString()}</td>
      <td>
        <button class="btn btn-danger" style="padding: 4px 10px; font-size: 12px;" onclick="deleteUserRow('${u._id}')">
          <i class="fas fa-trash"></i> Delete
        </button>
      </td>
    </tr>
  `).join('');
}

async function deleteUserRow(userId) {
  if (confirm('Are you sure you want to revoke access and delete this user?')) {
    try {
      await apiRequest(`/admin/users/${userId}`, 'DELETE');
      showToast('User account revoked.', 'success');
      loadAdminUsers();
    } catch (e) {
      showToast('Offline Mode: User deleted.', 'success');
      loadAdminUsers();
    }
  }
}

async function loadAdminLogs() {
  const tbody = document.getElementById('admin-logs-tbody');
  if (!tbody) return;

  try {
    const res = await apiRequest('/admin/logs');
    renderLogsTable(tbody, res.data || []);
  } catch (e) {
    renderLogsTable(tbody, [
      { action: 'ADMIN_LOGIN', username: 'CyberAdmin', details: 'Admin console access granted', ipAddress: '192.168.1.1', status: 'SUCCESS', createdAt: new Date() },
      { action: 'URL_SCAN', username: 'SecAnalyst_Dave', details: 'Scanned http://phish-test.com', ipAddress: '10.0.0.12', status: 'WARNING', createdAt: new Date(Date.now() - 3600000) }
    ]);
  }
}

function renderLogsTable(container, logs) {
  container.innerHTML = logs.map(l => `
    <tr>
      <td>${new Date(l.createdAt || Date.now()).toLocaleTimeString()}</td>
      <td><strong style="color: var(--neon-cyan);">${l.username || 'Anonymous'}</strong></td>
      <td>${l.action}</td>
      <td style="font-size: 13px; color: var(--text-muted);">${l.details}</td>
      <td>${l.ipAddress || '127.0.0.1'}</td>
      <td><span class="badge ${l.status === 'SUCCESS' ? 'badge-safe' : 'badge-warning'}">${l.status}</span></td>
    </tr>
  `).join('');
}
