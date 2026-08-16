/**
 * CyberShield AI — Enterprise Security Settings & Controls Logic
 * Connects all toggles, dropdowns, themes, preferences, data exports, and danger zone actions to real backend APIs.
 */

document.addEventListener('DOMContentLoaded', () => {
  requireAuth();
  initSettingsTabs();
  loadAllSettings();
  initSettingsFormHandlers();
});

let userProfileData = null;
let userSettingsData = null;

// Tab Switching
function initSettingsTabs() {
  const tabBtns = document.querySelectorAll('.settings-nav-btn');
  const panes = document.querySelectorAll('.settings-pane');

  tabBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      const targetId = btn.getAttribute('data-tab');
      tabBtns.forEach(b => b.classList.remove('active'));
      panes.forEach(p => p.classList.remove('active'));

      btn.classList.add('active');
      const targetPane = document.getElementById(targetId);
      if (targetPane) targetPane.classList.add('active');
    });
  });
}

// Load Settings from Backend
async function loadAllSettings() {
  try {
    // 1. Fetch Profile Data (for account info)
    const profRes = await apiRequest('/user/profile');
    if (profRes.success && profRes.data) {
      userProfileData = profRes.data;
      populateAccountFields(profRes.data);
    }

    // 2. Fetch Settings Data
    const settingsRes = await apiRequest('/user/settings');
    if (settingsRes.success && settingsRes.data) {
      userSettingsData = settingsRes.data;
      populateSettingsFields(settingsRes.data);
    }
  } catch (err) {
    console.error('[Settings Load Error]', err);
    showToast('Loaded local configuration preferences.', 'info');
  }
}

function populateAccountFields(data) {
  setVal('acc-fullname', data.fullName || data.username || '');
  setVal('acc-username', data.username || '');
  setVal('acc-email', data.email || 'Not configured');
  setVal('acc-phone', data.phoneNumber || '');
  setVal('acc-country', data.country || 'United States');
  setVal('acc-timezone', data.timezone || 'UTC-05:00 (EST)');
  setVal('acc-language', data.language || 'English (US)');
}

function populateSettingsFields(data) {
  // Security
  const sec = data.securityPreferences || {};
  setChecked('sec-toggle-2fa', userProfileData?.twoFactorEnabled || false);
  setChecked('sec-toggle-login-alerts', sec.loginAlerts !== false);
  setChecked('sec-toggle-new-device', sec.newDeviceAlerts !== false);
  setChecked('sec-toggle-suspicious', sec.suspiciousLoginDetection !== false);
  setVal('sec-session-timeout', sec.sessionTimeout || 60);

  // Notification Matrix
  const notif = data.notificationPreferences || {};
  setChecked('notif-crit-inapp', notif.criticalVulns?.inApp !== false);
  setChecked('notif-crit-email', notif.criticalVulns?.email !== false);
  setChecked('notif-high-inapp', notif.highVulns?.inApp !== false);
  setChecked('notif-high-email', notif.highVulns?.email !== false);
  setChecked('notif-med-inapp', notif.mediumVulns?.inApp !== false);
  setChecked('notif-med-email', !!notif.mediumVulns?.email);
  setChecked('notif-scan-inapp', notif.scanCompleted?.inApp !== false);
  setChecked('notif-scan-email', !!notif.scanCompleted?.email);
  setChecked('notif-mon-inapp', notif.monitoringAlerts?.inApp !== false);
  setChecked('notif-mon-email', notif.monitoringAlerts?.email !== false);
  setChecked('notif-copilot-inapp', notif.aiCopilotAlerts?.inApp !== false);
  setChecked('notif-copilot-email', !!notif.aiCopilotAlerts?.email);
  setChecked('notif-auth-inapp', notif.securityChanges?.inApp !== false);
  setChecked('notif-auth-email', notif.securityChanges?.email !== false);

  // Monitoring
  const mon = data.monitoringPreferences || {};
  setChecked('mon-toggle-continuous', mon.continuousMonitoring !== false);
  setChecked('mon-toggle-vuln', mon.vulnerabilityMonitoring !== false);
  setChecked('mon-toggle-attack-surface', mon.attackSurfaceMonitoring !== false);
  setVal('mon-scan-interval', mon.scanIntervalHours || 24);

  // AI Copilot
  const ai = data.aiCopilotPreferences || {};
  setChecked('copilot-toggle-master', ai.enabled !== false);
  setChecked('copilot-toggle-summaries', ai.autoSummaries !== false);
  setChecked('copilot-toggle-explanations', ai.threatExplanations !== false);
  setChecked('copilot-toggle-remediation', ai.investigationAssistance !== false);

  // Appearance
  const app = data.appearancePreferences || {};
  const currentSavedTheme = localStorage.getItem('cybershield_theme') || app.theme || 'dark';
  setVal('theme-selector', currentSavedTheme);
  const currentDensity = localStorage.getItem('cybershield_density') || app.layout || 'comfortable';
  setVal('density-selector', currentDensity);
  setChecked('theme-toggle-animations', app.animations !== false);

  // Privacy
  const priv = data.privacyPreferences || {};
  setVal('privacy-retention', priv.sessionHistoryRetention || 30);
}

function setVal(id, val) {
  const el = document.getElementById(id);
  if (el) el.value = val;
}

function setChecked(id, checked) {
  const el = document.getElementById(id);
  if (el) el.checked = !!checked;
}

function getChecked(id) {
  const el = document.getElementById(id);
  return el ? el.checked : false;
}

function getVal(id) {
  const el = document.getElementById(id);
  return el ? el.value : '';
}

// Event Handlers & API Submissions
function initSettingsFormHandlers() {
  // 1. Account Details Form
  const accForm = document.getElementById('form-account-settings');
  if (accForm) {
    accForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const fullName = getVal('acc-fullname').trim();
      const phoneNumber = getVal('acc-phone').trim();
      const timezone = getVal('acc-timezone');
      const language = getVal('acc-language');

      try {
        const res = await apiRequest('/user/profile', 'PUT', { fullName, phoneNumber, timezone, language });
        if (res.success) {
          showToast('Account parameters saved successfully.', 'success');
        } else {
          throw new Error(res.error || 'Failed to save');
        }
      } catch (err) {
        showToast(err.message || 'Error updating account.', 'danger');
      }
    });
  }

  // 2. Immediate Theme & Appearance Handler
  const themeSelector = document.getElementById('theme-selector');
  if (themeSelector) {
    themeSelector.addEventListener('change', (e) => {
      const selected = e.target.value;
      localStorage.setItem('cybershield_theme', selected);
      if (selected === 'light') {
        document.documentElement.setAttribute('data-theme', 'light');
      } else if (selected === 'system') {
        const isDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
        if (!isDark) document.documentElement.setAttribute('data-theme', 'light');
        else document.documentElement.removeAttribute('data-theme');
      } else {
        document.documentElement.removeAttribute('data-theme');
      }
      showToast(`Visual theme updated to: ${selected.toUpperCase()}`, 'info');
    });
  }

  const densitySelector = document.getElementById('density-selector');
  if (densitySelector) {
    densitySelector.addEventListener('change', (e) => {
      const selected = e.target.value;
      localStorage.setItem('cybershield_density', selected);
      if (selected === 'compact') {
        document.documentElement.setAttribute('data-density', 'compact');
      } else {
        document.documentElement.removeAttribute('data-density');
      }
      showToast(`Layout density updated to: ${selected.toUpperCase()}`, 'info');
    });
  }

  // 3. 2FA Switch in Security Tab
  const sec2faSwitch = document.getElementById('sec-toggle-2fa');
  if (sec2faSwitch) {
    sec2faSwitch.addEventListener('change', async () => {
      try {
        const res = await apiRequest('/user/2fa/toggle', 'POST');
        if (res.success) {
          showToast(res.message || '2FA setting updated.', 'success');
        }
      } catch (err) {
        showToast('Failed to toggle 2FA.', 'danger');
      }
    });
  }

  // 4. Save All Settings Master Button
  const saveAllBtn = document.getElementById('btn-save-all-settings');
  if (saveAllBtn) {
    saveAllBtn.addEventListener('click', async () => {
      saveAllBtn.disabled = true;
      saveAllBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Saving...';

      const payload = {
        notificationPreferences: {
          criticalVulns: { inApp: getChecked('notif-crit-inapp'), email: getChecked('notif-crit-email') },
          highVulns: { inApp: getChecked('notif-high-inapp'), email: getChecked('notif-high-email') },
          mediumVulns: { inApp: getChecked('notif-med-inapp'), email: getChecked('notif-med-email') },
          scanCompleted: { inApp: getChecked('notif-scan-inapp'), email: getChecked('notif-scan-email') },
          monitoringAlerts: { inApp: getChecked('notif-mon-inapp'), email: getChecked('notif-mon-email') },
          aiCopilotAlerts: { inApp: getChecked('notif-copilot-inapp'), email: getChecked('notif-copilot-email') },
          securityChanges: { inApp: getChecked('notif-auth-inapp'), email: getChecked('notif-auth-email') }
        },
        securityPreferences: {
          loginAlerts: getChecked('sec-toggle-login-alerts'),
          newDeviceAlerts: getChecked('sec-toggle-new-device'),
          suspiciousLoginDetection: getChecked('sec-toggle-suspicious'),
          sessionTimeout: parseInt(getVal('sec-session-timeout')) || 60
        },
        monitoringPreferences: {
          continuousMonitoring: getChecked('mon-toggle-continuous'),
          vulnerabilityMonitoring: getChecked('mon-toggle-vuln'),
          attackSurfaceMonitoring: getChecked('mon-toggle-attack-surface'),
          scanIntervalHours: parseInt(getVal('mon-scan-interval')) || 24
        },
        aiCopilotPreferences: {
          enabled: getChecked('copilot-toggle-master'),
          autoSummaries: getChecked('copilot-toggle-summaries'),
          threatExplanations: getChecked('copilot-toggle-explanations'),
          investigationAssistance: getChecked('copilot-toggle-remediation')
        },
        appearancePreferences: {
          theme: getVal('theme-selector') || 'dark',
          layout: getVal('density-selector') || 'comfortable',
          animations: getChecked('theme-toggle-animations')
        },
        privacyPreferences: {
          sessionHistoryRetention: parseInt(getVal('privacy-retention')) || 30
        }
      };

      try {
        const res = await apiRequest('/user/settings', 'PUT', payload);
        if (res.success) {
          showToast('All security settings saved successfully!', 'success');
        } else {
          throw new Error(res.error || 'Failed to save');
        }
      } catch (err) {
        showToast(err.message || 'Error saving settings.', 'danger');
      } finally {
        saveAllBtn.disabled = false;
        saveAllBtn.innerHTML = '<i class="fas fa-floppy-disk"></i> Save Changes';
      }
    });
  }

  // 5. Download My Data Export
  const downloadDataBtn = document.getElementById('btn-download-my-data');
  if (downloadDataBtn) {
    downloadDataBtn.addEventListener('click', async () => {
      showToast('Compiling complete account data archive...', 'info');
      try {
        const token = getToken();
        const res = await fetch(`${API_BASE}/user/export-data`, {
          headers: { 'Authorization': `Bearer ${token}` }
        });
        if (!res.ok) throw new Error('Failed to export data');

        const blob = await res.blob();
        const url = window.URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = `CyberShield_Account_Data_${Date.now()}.json`;
        document.body.appendChild(link);
        link.click();
        link.remove();
        window.URL.revokeObjectURL(url);
        showToast('Data archive downloaded successfully.', 'success');
      } catch (err) {
        showToast('Error exporting data: ' + err.message, 'danger');
      }
    });
  }

  // 6. Danger Zone Actions
  const btnLogoutAll = document.getElementById('btn-danger-logout-all');
  if (btnLogoutAll) {
    btnLogoutAll.addEventListener('click', async () => {
      if (!confirm('Are you sure you want to terminate all active sessions across all devices?')) return;
      try {
        const res = await apiRequest('/user/sessions/logout-others', 'POST');
        if (res.success) {
          showToast('All sessions invalidated.', 'success');
        }
      } catch (err) {
        showToast(err.message || 'Failed to logout sessions.', 'danger');
      }
    });
  }

  const btnDisableAcc = document.getElementById('btn-danger-disable-account');
  if (btnDisableAcc) {
    btnDisableAcc.addEventListener('click', async () => {
      if (!confirm('Disable your CyberShield account? You will need to contact an administrator to reactivate.')) return;
      try {
        const res = await apiRequest('/user/disable-account', 'POST');
        if (res.success) {
          showToast('Account disabled. Logging out...', 'warning');
          setTimeout(() => {
            removeToken();
            window.location.replace('login.html');
          }, 1500);
        }
      } catch (err) {
        showToast(err.message || 'Failed to disable account.', 'danger');
      }
    });
  }

  // 7. Delete Account Permanent Modal
  const btnDeleteAcc = document.getElementById('btn-danger-delete-account');
  const deleteModal = document.getElementById('delete-modal');
  const deleteBackdrop = document.getElementById('delete-modal-backdrop');
  const cancelDeleteBtn = document.getElementById('btn-cancel-delete');
  const deleteForm = document.getElementById('form-confirm-delete-account');

  const openDelete = () => {
    document.getElementById('modal-delete-password').value = '';
    deleteModal.style.display = 'block';
    deleteBackdrop.classList.add('active');
  };

  const closeDelete = () => {
    deleteModal.style.display = 'none';
    deleteBackdrop.classList.remove('active');
  };

  if (btnDeleteAcc) btnDeleteAcc.addEventListener('click', openDelete);
  if (cancelDeleteBtn) cancelDeleteBtn.addEventListener('click', closeDelete);
  if (deleteBackdrop) deleteBackdrop.addEventListener('click', closeDelete);

  if (deleteForm) {
    deleteForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const password = document.getElementById('modal-delete-password').value;
      if (!password) return showToast('Please enter your password to confirm.', 'warning');

      const confirmBtn = document.getElementById('btn-confirm-delete-submit');
      confirmBtn.disabled = true;
      confirmBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Deleting...';

      try {
        const res = await apiRequest('/user/account', 'DELETE', { password });
        if (res.success) {
          showToast('Account permanently deleted. Goodbye.', 'success');
          removeToken();
          localStorage.clear();
          setTimeout(() => {
            window.location.replace('index.html');
          }, 1500);
        } else {
          throw new Error(res.error || 'Failed to delete account');
        }
      } catch (err) {
        showToast(err.message || 'Incorrect password. Deletion aborted.', 'danger');
        confirmBtn.disabled = false;
        confirmBtn.innerHTML = '<i class="fas fa-trash"></i> Delete Forever';
      }
    });
  }
}
