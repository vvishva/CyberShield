/**
 * CyberShield AI — Security Identity Profile Logic
 * Connects to real backend APIs for profile, sessions, 2FA, password, and security ratings.
 */

document.addEventListener('DOMContentLoaded', () => {
  requireAuth();
  loadUserProfile();
  initProfileEventHandlers();
});

let currentProfileData = null;

async function loadUserProfile() {
  try {
    const res = await apiRequest('/user/profile');
    if (res.success && res.data) {
      currentProfileData = res.data;
      renderProfileUI(res.data);
    } else {
      throw new Error(res.error || 'Failed to load profile');
    }
  } catch (err) {
    console.error('[Profile Load Error]', err);
    showToast('Failed to load profile data from server.', 'danger');
  }
}

function renderProfileUI(data) {
  // Update sidebar user display
  setUser({
    id: data._id,
    username: data.username,
    fullName: data.fullName,
    email: data.email,
    phoneNumber: data.phoneNumber,
    role: data.role,
    avatar: data.avatar
  });

  const nameEl = document.getElementById('user-display-name');
  if (nameEl) nameEl.textContent = data.fullName || data.username;

  // 1. Profile Header
  const initial = (data.fullName || data.username || 'A').charAt(0).toUpperCase();
  setText('prof-initial', initial);
  setText('prof-full-name', data.fullName || data.username);
  setText('prof-username-tag', `@${data.username}`);
  setText('prof-role-badge', `${(data.role || 'USER').toUpperCase()} Clearance`);
  setText('prof-email-text', data.email || 'No email configured');
  setText('prof-phone-text', data.phoneNumber || 'No phone configured');

  const lastLoginDate = data.lastLoginAt ? new Date(data.lastLoginAt).toLocaleString() : 'Just now';
  setText('prof-last-login', lastLoginDate);
  setText('prof-last-device', data.lastLoginDevice || 'Authenticated Workstation');

  // Status Badge
  const statusBadge = document.getElementById('prof-status-badge');
  if (statusBadge) {
    statusBadge.className = `badge badge-${data.status === 'active' ? 'safe' : 'danger'}`;
    statusBadge.innerHTML = `<i class="fas fa-${data.status === 'active' ? 'circle-check' : 'circle-xmark'}"></i> ${(data.status || 'Active').toUpperCase()}`;
  }

  // 2. Security Rating
  const rating = data.securityRating || { score: 75, grade: 'Strong Security', checklist: [] };
  const scoreNum = document.getElementById('score-dial-number');
  const dialBox = document.getElementById('score-dial-box');
  const gradeText = document.getElementById('score-grade-text');

  if (scoreNum) scoreNum.textContent = rating.score;
  if (gradeText) {
    gradeText.textContent = rating.grade;
    gradeText.style.color = rating.score >= 80 ? 'var(--green)' : rating.score >= 60 ? 'var(--amber)' : 'var(--red)';
  }
  if (dialBox) {
    const borderColor = rating.score >= 80 ? 'var(--green)' : rating.score >= 60 ? 'var(--amber)' : 'var(--red)';
    dialBox.style.borderColor = borderColor;
  }

  // Checklist
  const checklistContainer = document.getElementById('score-checklist-container');
  if (checklistContainer && rating.checklist) {
    checklistContainer.innerHTML = rating.checklist.map(item => `
      <a href="${item.key === 'password' ? '#change-password' : item.key === '2fa' ? '#2fa' : 'settings.html'}" class="checklist-link-item ${item.status ? 'passed' : 'failed'}" onclick="${item.key === 'password' ? 'openPasswordModal(); return false;' : item.key === '2fa' ? 'trigger2FAToggle(); return false;' : ''}">
        <i class="fas ${item.status ? 'fa-circle-check' : 'fa-circle-xmark'}"></i>
        <span>${escapeHtml(item.label)}</span>
      </a>
    `).join('');
  }

  // 3. Personal Information Table
  setText('info-full-name', data.fullName || data.username);
  setText('info-username', data.username);
  setText('info-email', data.email || 'Not configured');
  setText('info-phone', data.phoneNumber || 'Not configured');
  setText('info-country', data.country || 'United States');
  setText('info-timezone', data.timezone || 'UTC-05:00 (EST)');
  setText('info-created-at', data.createdAt ? new Date(data.createdAt).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' }) : 'Aug 2026');

  // 4. Security & Authentication Controls
  const btn2fa = document.getElementById('btn-toggle-2fa');
  if (btn2fa) {
    btn2fa.className = `btn btn-${data.twoFactorEnabled ? 'success' : 'secondary'} btn-sm`;
    btn2fa.innerHTML = data.twoFactorEnabled ? '<i class="fas fa-lock"></i> 2FA Enabled' : '<i class="fas fa-shield"></i> Enable 2FA';
  }

  const badgeEmail = document.getElementById('badge-email-status');
  if (badgeEmail) {
    badgeEmail.className = `badge badge-${data.isVerified ? 'safe' : 'warning'}`;
    badgeEmail.innerHTML = data.isVerified ? '<i class="fas fa-check"></i> Verified' : '<i class="fas fa-clock"></i> Unverified';
  }

  const badgePhone = document.getElementById('badge-phone-status');
  if (badgePhone) {
    badgePhone.className = `badge badge-${data.phoneVerified ? 'safe' : 'info'}`;
    badgePhone.innerHTML = data.phoneVerified ? '<i class="fas fa-check"></i> Verified' : data.phoneNumber ? '<i class="fas fa-phone"></i> Configured' : '<i class="fas fa-plus"></i> Not Set';
  }

  const passAge = data.passwordChangedAt 
    ? Math.floor((Date.now() - new Date(data.passwordChangedAt).getTime()) / (1000 * 60 * 60 * 24))
    : 0;
  setText('info-password-age', passAge === 0 ? 'Today' : `${passAge} days ago`);

  // 5. Active Sessions List
  renderSessions(data.sessions || []);

  // 6. Connected Accounts
  renderConnectedAccounts(data.connectedAccounts || {});

  // 7. Security Activity Timeline
  renderSecurityActivity(data.securityActivity || []);
}

function renderSessions(sessions) {
  const container = document.getElementById('sessions-container');
  if (!container) return;

  if (sessions.length === 0) {
    container.innerHTML = '<div style="text-align:center; padding:20px; color:var(--text-muted);">No active sessions recorded.</div>';
    return;
  }

  container.innerHTML = sessions.map(s => {
    let devIcon = 'fa-desktop';
    if (/android|mobile|iphone/i.test(s.device || s.os)) devIcon = 'fa-mobile-screen-button';
    else if (/tablet|ipad/i.test(s.device || s.os)) devIcon = 'fa-tablet-screen-button';
    else if (/mac/i.test(s.os)) devIcon = 'fa-laptop';

    const lastActiveStr = s.current ? 'Active Now' : new Date(s.lastActive || s.createdAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    const sessionId = s.sessionId || s._id;

    return `
      <div class="session-card ${s.current ? 'current' : ''}">
        <div style="display:flex; align-items:center; gap:14px;">
          <div style="width:38px; height:38px; border-radius:var(--radius-sm); background:var(--bg-glass); border:1px solid var(--border-subtle); display:flex; align-items:center; justify-content:center; font-size:18px; color:var(--cyan); flex-shrink:0;">
            <i class="fas ${devIcon}"></i>
          </div>
          <div>
            <div style="display:flex; align-items:center; gap:8px; flex-wrap:wrap;">
              <strong style="font-size:13.5px; color:var(--text-primary);">${escapeHtml(s.os || 'OS')} — ${escapeHtml(s.browser || 'Browser')}</strong>
              ${s.current ? '<span class="badge badge-safe" style="font-size:10px;"><span class="pulse-dot"></span> Current Session</span>' : ''}
            </div>
            <div style="font-size:12px; color:var(--text-muted); margin-top:2px;">
              <span>IP: <code style="color:var(--text-secondary);">${escapeHtml(s.ip || '127.0.0.1')}</code></span> • 
              <span>${escapeHtml(s.location || 'Network')}</span> • 
              <span>Last Active: ${lastActiveStr}</span>
            </div>
          </div>
        </div>
        <div>
          ${!s.current ? `<button class="btn btn-secondary btn-sm" onclick="terminateSession('${sessionId}')" title="Logout this session"><i class="fas fa-power-off text-danger"></i> Terminate</button>` : '<span style="font-size:11px; color:var(--green); font-weight:600;"><i class="fas fa-shield"></i> This Device</span>'}
        </div>
      </div>
    `;
  }).join('');
}

function renderConnectedAccounts(accounts) {
  const container = document.getElementById('connected-accounts-grid');
  if (!container) return;

  const google = accounts.google || { connected: false, label: 'Google Workspace' };
  const email = accounts.email || { connected: true, label: 'Email Credentials' };
  const mobile = accounts.mobile || { connected: false, label: 'Mobile SMS Gateway' };

  container.innerHTML = `
    <!-- Google OAuth Card -->
    <div style="padding:18px; background:rgba(255,255,255,0.02); border:1px solid var(--border-subtle); border-radius:var(--radius-md); display:flex; justify-content:space-between; align-items:center;">
      <div style="display:flex; align-items:center; gap:12px;">
        <div style="width:36px; height:36px; border-radius:50%; background:rgba(66, 133, 244, 0.15); color:#4285f4; display:flex; align-items:center; justify-content:center; font-size:18px;">
          <i class="fab fa-google"></i>
        </div>
        <div>
          <h4 style="font-size:13.5px; margin:0; color:var(--text-primary);">Google Workspace</h4>
          <p style="font-size:11.5px; color:var(--text-muted); margin:2px 0 0;">${google.connected ? escapeHtml(google.email || 'Linked') : 'Not connected'}</p>
        </div>
      </div>
      <div>
        ${google.connected ? `
          <button class="btn btn-secondary btn-sm" onclick="disconnectAccountProvider('google')">Disconnect</button>
        ` : `
          <a href="login.html" class="btn btn-primary btn-sm"><i class="fas fa-plus"></i> Connect</a>
        `}
      </div>
    </div>

    <!-- Email Card -->
    <div style="padding:18px; background:rgba(255,255,255,0.02); border:1px solid var(--border-subtle); border-radius:var(--radius-md); display:flex; justify-content:space-between; align-items:center;">
      <div style="display:flex; align-items:center; gap:12px;">
        <div style="width:36px; height:36px; border-radius:50%; background:var(--cyan-dim); color:var(--cyan); display:flex; align-items:center; justify-content:center; font-size:16px;">
          <i class="fas fa-envelope"></i>
        </div>
        <div>
          <h4 style="font-size:13.5px; margin:0; color:var(--text-primary);">Primary Email</h4>
          <p style="font-size:11.5px; color:var(--text-muted); margin:2px 0 0;">${escapeHtml(email.value || 'Active')}</p>
        </div>
      </div>
      <span class="badge badge-safe"><i class="fas fa-check"></i> Connected</span>
    </div>

    <!-- Mobile SMS Card -->
    <div style="padding:18px; background:rgba(255,255,255,0.02); border:1px solid var(--border-subtle); border-radius:var(--radius-md); display:flex; justify-content:space-between; align-items:center;">
      <div style="display:flex; align-items:center; gap:12px;">
        <div style="width:36px; height:36px; border-radius:50%; background:var(--green-dim); color:var(--green); display:flex; align-items:center; justify-content:center; font-size:16px;">
          <i class="fas fa-mobile-screen"></i>
        </div>
        <div>
          <h4 style="font-size:13.5px; margin:0; color:var(--text-primary);">Mobile SMS Alert Gateway</h4>
          <p style="font-size:11.5px; color:var(--text-muted); margin:2px 0 0;">${escapeHtml(mobile.value || 'Not configured')}</p>
        </div>
      </div>
      <button class="btn btn-secondary btn-sm" onclick="openEditModal()">${mobile.connected ? 'Update' : 'Configure'}</button>
    </div>
  `;
}

function renderSecurityActivity(activity) {
  const container = document.getElementById('security-activity-list');
  if (!container) return;

  if (activity.length === 0) {
    container.innerHTML = '<div style="text-align:center; padding:20px; color:var(--text-muted);">No security events recorded.</div>';
    return;
  }

  container.innerHTML = activity.map(a => {
    const statusColor = a.status === 'CRITICAL' ? 'danger' : a.status === 'WARNING' ? 'warning' : 'safe';
    const statusIcon = a.status === 'CRITICAL' ? 'fa-triangle-exclamation' : a.status === 'WARNING' ? 'fa-shield-halved' : 'fa-check';
    const timeStr = a.timestamp ? new Date(a.timestamp).toLocaleString() : 'Recent';

    return `
      <div style="display:flex; align-items:center; justify-content:space-between; padding:12px 14px; background:rgba(255,255,255,0.015); border:1px solid var(--border-subtle); border-radius:var(--radius-sm); gap:12px;">
        <div style="display:flex; align-items:center; gap:12px;">
          <span class="badge badge-${statusColor}" style="padding:4px 8px;"><i class="fas ${statusIcon}"></i> ${escapeHtml(a.status || 'INFO')}</span>
          <div>
            <strong style="font-size:13px; color:var(--text-primary);">${escapeHtml(a.event)}</strong>
            <div style="font-size:11.5px; color:var(--text-muted); margin-top:2px;">
              <span>IP: <code>${escapeHtml(a.ip || '127.0.0.1')}</code></span> • 
              <span>${escapeHtml(a.device || 'Workstation')}</span>
            </div>
          </div>
        </div>
        <span style="font-size:11.5px; color:var(--text-muted); white-space:nowrap;">${timeStr}</span>
      </div>
    `;
  }).join('');
}

function setText(id, text) {
  const el = document.getElementById(id);
  if (el) el.textContent = text;
}

// ============================================================
// MODAL & ACTION HANDLERS
// ============================================================

function initProfileEventHandlers() {
  // Edit Profile Modal Buttons
  const openEditBtn = document.getElementById('btn-open-edit-modal');
  const quickEditBtn = document.getElementById('btn-quick-edit-profile');
  const editPersonalBtn = document.getElementById('btn-edit-personal-info');
  const closeEditBtn = document.getElementById('btn-close-edit-modal');
  const cancelEditBtn = document.getElementById('btn-cancel-edit-modal');
  const editBackdrop = document.getElementById('edit-profile-backdrop');

  const openEdit = () => {
    if (currentProfileData) {
      document.getElementById('modal-edit-fullname').value = currentProfileData.fullName || currentProfileData.username || '';
      document.getElementById('modal-edit-phone').value = currentProfileData.phoneNumber || '';
      document.getElementById('modal-edit-country').value = currentProfileData.country || 'United States';
      document.getElementById('modal-edit-timezone').value = currentProfileData.timezone || 'UTC-05:00';
      document.getElementById('modal-edit-language').value = currentProfileData.language || 'English (US)';
    }
    document.getElementById('edit-profile-modal').style.display = 'block';
    editBackdrop.classList.add('active');
  };

  const closeEdit = () => {
    document.getElementById('edit-profile-modal').style.display = 'none';
    editBackdrop.classList.remove('active');
  };

  if (openEditBtn) openEditBtn.addEventListener('click', openEdit);
  if (quickEditBtn) quickEditBtn.addEventListener('click', openEdit);
  if (editPersonalBtn) editPersonalBtn.addEventListener('click', openEdit);
  if (closeEditBtn) closeEditBtn.addEventListener('click', closeEdit);
  if (cancelEditBtn) cancelEditBtn.addEventListener('click', closeEdit);
  if (editBackdrop) editBackdrop.addEventListener('click', closeEdit);

  window.openEditModal = openEdit;

  // Edit Profile Form Submission
  const editForm = document.getElementById('edit-profile-form');
  if (editForm) {
    editForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const fullName = document.getElementById('modal-edit-fullname').value.trim();
      const phoneNumber = document.getElementById('modal-edit-phone').value.trim();
      const country = document.getElementById('modal-edit-country').value.trim();
      const timezone = document.getElementById('modal-edit-timezone').value.trim();
      const language = document.getElementById('modal-edit-language').value;

      const saveBtn = document.getElementById('btn-save-profile-modal');
      saveBtn.disabled = true;
      saveBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Saving...';

      try {
        const res = await apiRequest('/user/profile', 'PUT', { fullName, phoneNumber, country, timezone, language });
        if (res.success) {
          showToast('Profile information updated successfully!', 'success');
          closeEdit();
          await loadUserProfile();
        } else {
          throw new Error(res.error || 'Failed to update');
        }
      } catch (err) {
        showToast(err.message || 'Error updating profile.', 'danger');
      } finally {
        saveBtn.disabled = false;
        saveBtn.innerHTML = '<i class="fas fa-floppy-disk"></i> Save Profile';
      }
    });
  }

  // Change Password Modal
  const openPassBtn = document.getElementById('btn-open-change-password');
  const closePassBtn = document.getElementById('btn-close-password-modal');
  const cancelPassBtn = document.getElementById('btn-cancel-password-modal');
  const passBackdrop = document.getElementById('password-modal-backdrop');

  const openPass = () => {
    document.getElementById('modal-current-password').value = '';
    document.getElementById('modal-new-password').value = '';
    document.getElementById('modal-confirm-password').value = '';
    document.getElementById('password-modal').style.display = 'block';
    passBackdrop.classList.add('active');
  };

  const closePass = () => {
    document.getElementById('password-modal').style.display = 'none';
    passBackdrop.classList.remove('active');
  };

  if (openPassBtn) openPassBtn.addEventListener('click', openPass);
  if (closePassBtn) closePassBtn.addEventListener('click', closePass);
  if (cancelPassBtn) cancelPassBtn.addEventListener('click', closePass);
  if (passBackdrop) passBackdrop.addEventListener('click', closePass);

  window.openPasswordModal = openPass;

  // Change Password Form Submission
  const passForm = document.getElementById('change-password-form');
  if (passForm) {
    passForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const currentPassword = document.getElementById('modal-current-password').value;
      const newPassword = document.getElementById('modal-new-password').value;
      const confirmPassword = document.getElementById('modal-confirm-password').value;

      if (newPassword !== confirmPassword) {
        return showToast('New passwords do not match.', 'warning');
      }

      if (newPassword.length < 8) {
        return showToast('Password must be at least 8 characters long.', 'warning');
      }

      const submitBtn = document.getElementById('btn-submit-password-change');
      submitBtn.disabled = true;
      submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Updating...';

      try {
        const res = await apiRequest('/user/password', 'PUT', { currentPassword, newPassword });
        if (res.success) {
          showToast('Account password updated successfully!', 'success');
          closePass();
          await loadUserProfile();
        } else {
          throw new Error(res.error || 'Failed to update password');
        }
      } catch (err) {
        showToast(err.message || 'Incorrect password.', 'danger');
      } finally {
        submitBtn.disabled = false;
        submitBtn.innerHTML = '<i class="fas fa-check"></i> Update Password';
      }
    });
  }

  // 2FA Toggle Action
  const btn2fa = document.getElementById('btn-toggle-2fa');
  if (btn2fa) {
    btn2fa.addEventListener('click', trigger2FAToggle);
  }

  // Logout All Other Sessions Button
  const btnLogoutOthers = document.getElementById('btn-logout-other-sessions');
  if (btnLogoutOthers) {
    btnLogoutOthers.addEventListener('click', async () => {
      if (!confirm('Are you sure you want to terminate all other active device sessions?')) return;
      try {
        const res = await apiRequest('/user/sessions/logout-others', 'POST');
        if (res.success) {
          showToast('All other device sessions have been terminated.', 'success');
          renderSessions(res.data || []);
        } else {
          throw new Error(res.error || 'Failed to logout sessions');
        }
      } catch (err) {
        showToast(err.message || 'Error terminating sessions.', 'danger');
      }
    });
  }
}

async function trigger2FAToggle() {
  try {
    const res = await apiRequest('/user/2fa/toggle', 'POST');
    if (res.success) {
      showToast(res.message || '2FA setting updated.', 'success');
      await loadUserProfile();
    } else {
      throw new Error(res.error || 'Failed to toggle 2FA');
    }
  } catch (err) {
    showToast(err.message || 'Error updating 2FA.', 'danger');
  }
}

async function terminateSession(sessionId) {
  if (!confirm('Terminate this device session?')) return;
  try {
    const res = await apiRequest(`/user/sessions/${sessionId}`, 'DELETE');
    if (res.success) {
      showToast('Device session terminated successfully.', 'success');
      renderSessions(res.data || []);
    } else {
      throw new Error(res.error || 'Failed to terminate session');
    }
  } catch (err) {
    showToast(err.message || 'Error terminating session.', 'danger');
  }
}

async function disconnectAccountProvider(provider) {
  if (!confirm(`Disconnect ${provider} account authentication?`)) return;
  try {
    const res = await apiRequest('/user/disconnect-account', 'POST', { provider });
    if (res.success) {
      showToast(res.message || 'Provider disconnected.', 'success');
      await loadUserProfile();
    } else {
      throw new Error(res.error || 'Failed to disconnect');
    }
  } catch (err) {
    showToast(err.message || 'Error disconnecting account.', 'danger');
  }
}

window.terminateSession = terminateSession;
window.disconnectAccountProvider = disconnectAccountProvider;
window.trigger2FAToggle = trigger2FAToggle;
