/**
 * CyberShield AI — SOC Notification Center Logic
 * Connects to real backend Notification APIs, filtering, real-time SSE stream, and detail inspection drawer.
 */

document.addEventListener('DOMContentLoaded', () => {
  requireAuth();
  initNotificationControls();
  loadNotificationsFeed();
  initLiveSSEStream();
});

let currentFilterCategory = 'all';
let currentFilterRead = 'all';
let currentSearchQuery = '';
let currentNotificationsList = [];
let activeDrawerNotification = null;

function initNotificationControls() {
  // Category filter pills
  const pills = document.querySelectorAll('.notif-filter-pill');
  pills.forEach(pill => {
    pill.addEventListener('click', () => {
      pills.forEach(p => p.classList.remove('active'));
      pill.classList.add('active');
      currentFilterCategory = pill.getAttribute('data-category') || 'all';
      loadNotificationsFeed();
    });
  });

  // Read filter dropdown
  const readFilter = document.getElementById('notif-read-filter');
  if (readFilter) {
    readFilter.addEventListener('change', (e) => {
      currentFilterRead = e.target.value;
      loadNotificationsFeed();
    });
  }

  // Search input with debounce
  const searchInput = document.getElementById('notif-search-input');
  let searchTimeout = null;
  if (searchInput) {
    searchInput.addEventListener('input', (e) => {
      clearTimeout(searchTimeout);
      searchTimeout = setTimeout(() => {
        currentSearchQuery = e.target.value.trim();
        loadNotificationsFeed();
      }, 300);
    });
  }

  // Mark all read button
  const markAllBtn = document.getElementById('btn-mark-all-read');
  if (markAllBtn) {
    markAllBtn.addEventListener('click', async () => {
      try {
        const res = await apiRequest('/notifications/read-all', 'PUT');
        if (res.success) {
          showToast('All notifications marked as read.', 'success');
          loadNotificationsFeed();
          if (typeof updateUnreadNotifBadge === 'function') updateUnreadNotifBadge();
        }
      } catch (err) {
        showToast('Failed to mark all as read.', 'danger');
      }
    });
  }

  // Clear read notifications button
  const clearReadBtn = document.getElementById('btn-clear-read-notifs');
  if (clearReadBtn) {
    clearReadBtn.addEventListener('click', async () => {
      if (!confirm('Clear all read notifications from your history?')) return;
      try {
        const res = await apiRequest('/notifications/clear-read', 'DELETE');
        if (res.success) {
          showToast('Read notifications cleared.', 'success');
          loadNotificationsFeed();
          if (typeof updateUnreadNotifBadge === 'function') updateUnreadNotifBadge();
        }
      } catch (err) {
        showToast('Failed to clear read notifications.', 'danger');
      }
    });
  }

  // Drawer Close Handlers
  const closeDrawerBtn = document.getElementById('btn-close-notif-drawer');
  const drawerBackdrop = document.getElementById('notif-drawer-backdrop');
  if (closeDrawerBtn) closeDrawerBtn.addEventListener('click', closeNotifDrawer);
  if (drawerBackdrop) drawerBackdrop.addEventListener('click', closeNotifDrawer);

  // Drawer Toggle Read Button
  const drawerToggleRead = document.getElementById('btn-drawer-toggle-read');
  if (drawerToggleRead) {
    drawerToggleRead.addEventListener('click', async () => {
      if (!activeDrawerNotification) return;
      try {
        const res = await apiRequest(`/notifications/${activeDrawerNotification._id}/read`, 'PUT');
        if (res.success) {
          showToast('Notification marked as read.', 'success');
          activeDrawerNotification.read = true;
          drawerToggleRead.innerHTML = '<i class="fas fa-check"></i> Read';
          drawerToggleRead.disabled = true;
          loadNotificationsFeed();
          if (typeof updateUnreadNotifBadge === 'function') updateUnreadNotifBadge();
        }
      } catch (e) {}
    });
  }
}

async function loadNotificationsFeed() {
  const container = document.getElementById('notifications-feed-list');
  if (!container) return;

  const params = new URLSearchParams();
  if (currentFilterCategory !== 'all') params.append('category', currentFilterCategory);
  if (currentFilterRead !== 'all') params.append('read', currentFilterRead);
  if (currentSearchQuery) params.append('search', currentSearchQuery);

  try {
    const res = await apiRequest(`/notifications?${params.toString()}`);
    if (res.success && res.data) {
      currentNotificationsList = res.data;
      renderNotificationCards(res.data);
      if (typeof updateUnreadNotifBadge === 'function') updateUnreadNotifBadge();
    } else {
      throw new Error(res.error || 'Failed to load');
    }
  } catch (err) {
    console.error('[Notification Load Error]', err);
    container.innerHTML = `
      <div class="glass-card" style="text-align:center; padding:40px; color:var(--text-muted);">
        <i class="fas fa-triangle-exclamation" style="font-size:28px; color:var(--amber); margin-bottom:12px;"></i>
        <p style="color:var(--text-primary); font-weight:600; margin-bottom:6px;">Unable to load notifications</p>
        <p style="font-size:13px; margin-bottom:16px;">${escapeHtml(err.message || 'Please check server connection.')}</p>
        <button class="btn btn-secondary btn-sm" onclick="loadNotificationsFeed()"><i class="fas fa-rotate"></i> Retry</button>
      </div>
    `;
  }
}

function renderNotificationCards(notifications) {
  const container = document.getElementById('notifications-feed-list');
  if (!container) return;

  if (notifications.length === 0) {
    container.innerHTML = `
      <div class="glass-card" style="text-align:center; padding:48px 20px; color:var(--text-muted);">
        <i class="fas fa-bell-slash" style="font-size:36px; color:var(--border-glass); margin-bottom:14px;"></i>
        <h3 style="font-size:16px; font-weight:700; color:var(--text-primary); margin-bottom:4px;">No Notifications Found</h3>
        <p style="font-size:13px; color:var(--text-secondary); max-width:400px; margin:0 auto;">There are no alerts matching your current filter criteria. All monitored endpoints are operating within normal security parameters.</p>
      </div>
    `;
    return;
  }

  container.innerHTML = notifications.map(item => {
    const sev = (item.severity || 'INFO').toUpperCase();
    let sevBadge = 'badge-info';
    let iconClass = 'fa-info-circle';
    let iconCat = item.category || 'security';

    if (sev === 'CRITICAL') {
      sevBadge = 'badge-critical';
      iconClass = 'fa-skull-crossbones';
      iconCat = 'critical';
    } else if (sev === 'HIGH') {
      sevBadge = 'badge-danger';
      iconClass = 'fa-triangle-exclamation';
      iconCat = 'security';
    } else if (sev === 'MEDIUM') {
      sevBadge = 'badge-warning';
      iconClass = 'fa-shield-halved';
      iconCat = 'monitoring';
    } else if (sev === 'LOW') {
      sevBadge = 'badge-info';
      iconClass = 'fa-radar';
      iconCat = 'system';
    } else if (sev === 'INFO') {
      sevBadge = 'badge-safe';
      iconClass = 'fa-check';
      iconCat = 'account';
    }

    const timeAgo = formatTimeAgo(item.createdAt);

    return `
      <div class="notif-card-item ${!item.read ? 'unread' : ''} ${!item.read && sev === 'CRITICAL' ? 'severity-critical' : ''}" onclick="openNotifInspection('${item._id}')">
        <div class="notif-icon-box ${iconCat}">
          <i class="fas ${iconClass}"></i>
        </div>

        <div style="flex:1; min-width:0;">
          <div style="display:flex; align-items:center; justify-content:space-between; gap:10px; margin-bottom:4px; flex-wrap:wrap;">
            <div style="display:flex; align-items:center; gap:8px;">
              <span class="badge ${sevBadge}" style="font-size:10px;">${sev}</span>
              <span style="font-size:11px; font-family:var(--font-mono); color:var(--text-muted);">${escapeHtml(item.eventId || 'EVT-000000')}</span>
              ${!item.read ? '<span class="pulse-dot" style="background:var(--cyan); box-shadow:0 0 8px var(--cyan);" title="Unread Alert"></span>' : ''}
            </div>
            <span style="font-size:11.5px; color:var(--text-muted);">${timeAgo}</span>
          </div>

          <h4 style="font-size:14px; font-weight:700; color:var(--text-primary); margin-bottom:4px;">${escapeHtml(item.title)}</h4>
          <p style="font-size:12.5px; color:var(--text-secondary); line-height:1.4; margin-bottom:8px;">${escapeHtml(item.message)}</p>

          <div style="display:flex; align-items:center; justify-content:space-between; gap:10px; flex-wrap:wrap;">
            <div style="display:flex; align-items:center; gap:8px; font-size:11.5px; color:var(--text-muted);">
              <span><i class="fas fa-server text-cyan"></i> <code>${escapeHtml(item.asset || 'CyberShield Core')}</code></span>
              <span>•</span>
              <span><i class="fas fa-shield"></i> ${escapeHtml(item.source || 'Engine')}</span>
            </div>

            <div style="display:flex; gap:6px;" onclick="event.stopPropagation();">
              ${!item.read ? `<button class="btn btn-secondary btn-sm" onclick="markSingleRead('${item._id}')" title="Mark as read"><i class="fas fa-check"></i></button>` : ''}
              <button class="btn btn-secondary btn-sm" onclick="deleteSingleNotif('${item._id}')" title="Delete alert"><i class="fas fa-trash"></i></button>
            </div>
          </div>
        </div>
      </div>
    `;
  }).join('');
}

function openNotifInspection(id) {
  const notif = currentNotificationsList.find(n => n._id === id);
  if (!notif) return;

  activeDrawerNotification = notif;

  setText('drawer-event-id', notif.eventId || 'EVT-000000');
  setText('drawer-title', notif.title);
  setText('drawer-timestamp', new Date(notif.createdAt).toLocaleString());
  setText('drawer-asset', notif.asset || 'CyberShield Sentinel');
  setText('drawer-source', notif.source || 'Security Engine');
  setText('drawer-message', notif.message);
  setText('drawer-action-rec', notif.recommendedAction || 'Perform standard security triage and inspect endpoint configuration.');
  setText('drawer-action-label', notif.actionLabel || 'View Finding');

  const actionLink = document.getElementById('btn-drawer-action-link');
  if (actionLink) {
    actionLink.href = notif.actionUrl || 'scanner.html';
  }

  const sevBadge = document.getElementById('drawer-severity-badge');
  if (sevBadge) {
    const sev = (notif.severity || 'INFO').toUpperCase();
    sevBadge.textContent = sev;
    sevBadge.className = `badge badge-${sev === 'CRITICAL' ? 'critical' : sev === 'HIGH' ? 'danger' : sev === 'MEDIUM' ? 'warning' : 'safe'}`;
  }

  const readBtn = document.getElementById('btn-drawer-toggle-read');
  if (readBtn) {
    readBtn.innerHTML = notif.read ? '<i class="fas fa-check"></i> Read' : '<i class="fas fa-check"></i> Mark as Read';
    readBtn.disabled = notif.read;
  }

  document.getElementById('notif-inspection-drawer').classList.add('open');
  document.getElementById('notif-drawer-backdrop').classList.add('active');

  // Auto-mark as read on open if unread
  if (!notif.read) {
    markSingleRead(notif._id, false);
  }
}

function closeNotifDrawer() {
  document.getElementById('notif-inspection-drawer').classList.remove('open');
  document.getElementById('notif-drawer-backdrop').classList.remove('active');
  activeDrawerNotification = null;
}

async function markSingleRead(id, refresh = true) {
  try {
    const res = await apiRequest(`/notifications/${id}/read`, 'PUT');
    if (res.success) {
      if (refresh) {
        showToast('Marked as read.', 'success');
        loadNotificationsFeed();
      }
      if (typeof updateUnreadNotifBadge === 'function') updateUnreadNotifBadge();
    }
  } catch (e) {}
}

async function deleteSingleNotif(id) {
  try {
    const res = await apiRequest(`/notifications/${id}`, 'DELETE');
    if (res.success) {
      showToast('Notification deleted.', 'info');
      loadNotificationsFeed();
      if (typeof updateUnreadNotifBadge === 'function') updateUnreadNotifBadge();
    }
  } catch (e) {
    showToast('Failed to delete notification.', 'danger');
  }
}

function initLiveSSEStream() {
  try {
    const token = getToken();
    const eventSource = new EventSource(`${API_BASE}/events/feed${token ? '?token=' + encodeURIComponent(token) : ''}`);

    eventSource.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        if (data.type === 'notification' || data.type === 'scan_complete' || data.type === 'threat_alert') {
          showToast(`🔔 New SOC Alert: ${data.title || 'Security finding detected'}`, 'warning');
          loadNotificationsFeed();
          if (typeof updateUnreadNotifBadge === 'function') updateUnreadNotifBadge();
        }
      } catch (e) {}
    };

    eventSource.onerror = () => {
      eventSource.close();
    };
  } catch (e) {}
}

function formatTimeAgo(dateStr) {
  if (!dateStr) return 'Just now';
  const diffMs = Date.now() - new Date(dateStr).getTime();
  const mins = Math.floor(diffMs / (1000 * 60));
  if (mins < 1) return 'Just now';
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

function setText(id, text) {
  const el = document.getElementById(id);
  if (el) el.textContent = text;
}

window.openNotifInspection = openNotifInspection;
window.markSingleRead = markSingleRead;
window.deleteSingleNotif = deleteSingleNotif;
