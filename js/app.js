/**
 * CyberShield - Main Application Core & Global Utilities
 * Optimized for Desktop and Mobile Browsers (iOS / Android / Chrome / Safari).
 */

// Auto-detect: local development uses /api, production uses full Render URL
const API_BASE = (window.location.hostname === 'localhost' || 
                  window.location.hostname === '127.0.0.1' || 
                  window.location.hostname.startsWith('192.168.') || 
                  window.location.hostname.startsWith('10.'))
  ? '/api'
  : 'https://cybershield-backend-uhwn.onrender.com/api';

// Toast & Browser Notification Manager
function showToast(message, type = 'info') {
  let container = document.getElementById('toast-container');
  if (!container) {
    container = document.createElement('div');
    container.id = 'toast-container';
    document.body.appendChild(container);
  }

  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  let icon = 'fa-info-circle';
  if (type === 'success') icon = 'fa-check-circle';
  if (type === 'danger') icon = 'fa-exclamation-triangle';
  if (type === 'warning') icon = 'fa-shield-alt';

  toast.innerHTML = `<i class="fas ${icon}"></i> <span>${message}</span>`;
  container.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = '0';
    setTimeout(() => toast.remove(), 300);
  }, 3500);
}

// HTML Escape utility
function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// Token & Session Storage Helpers
function getToken() {
  return localStorage.getItem('cybershield_token') || sessionStorage.getItem('cybershield_token');
}

function setToken(token, remember = true) {
  localStorage.setItem('cybershield_token', token);
  sessionStorage.setItem('cybershield_token', token);
}

function removeToken() {
  localStorage.removeItem('cybershield_token');
  sessionStorage.removeItem('cybershield_token');
}

function getUser() {
  const uStr = localStorage.getItem('cybershield_user') || sessionStorage.getItem('cybershield_user');
  if (uStr) {
    try { return JSON.parse(uStr); } catch (e) {}
  }
  return { username: 'SecAnalyst', email: 'user@cybershield.io', role: 'user' };
}

function setUser(user, remember = true) {
  const str = JSON.stringify(user);
  localStorage.setItem('cybershield_user', str);
  sessionStorage.setItem('cybershield_user', str);
}

// Authentication Guard
function requireAuth() {
  const token = getToken();
  if (!token) {
    window.location.replace('login.html?t=' + Date.now());
  }
}

// Global API Fetch Helper
async function apiRequest(endpoint, method = 'GET', body = null) {
  const headers = { 'Content-Type': 'application/json' };
  const token = getToken();
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  const opts = { method, headers };
  if (body) opts.body = JSON.stringify(body);

  try {
    const res = await fetch(`${API_BASE}${endpoint}`, opts);
    const data = await res.json();
    if (!res.ok) {
      throw new Error(data.error || 'API Request Failed');
    }
    return data;
  } catch (err) {
    console.warn(`[API Notice] ${endpoint}: ${err.message}. Using fallback engine.`);
    throw err;
  }
}

// Centralized Reusable PDF Report Download Helper
async function downloadReportPDF(params = {}, defaultFilename = 'CyberShield_Security_Report.pdf') {
  try {
    showToast('Generating PDF report...', 'info');

    const token = getToken();
    const headers = { 'Content-Type': 'application/json' };
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }

    const payload = typeof params === 'string' ? { scanId: params } : (params || {});

    const res = await fetch(`${API_BASE}/reports/download-pdf`, {
      method: 'POST',
      headers,
      body: JSON.stringify(payload)
    });

    if (!res.ok) {
      const errorJson = await res.json().catch(() => ({}));
      throw new Error(errorJson.error || `Server error: ${res.status}`);
    }

    const contentType = res.headers.get('Content-Type') || '';
    if (!contentType.includes('application/pdf')) {
      throw new Error('Response is not a PDF binary stream.');
    }

    const blob = await res.blob();
    if (!blob || blob.size === 0) {
      throw new Error('Generated PDF report buffer was empty.');
    }

    let filename = defaultFilename;
    const disposition = res.headers.get('Content-Disposition');
    if (disposition && disposition.includes('filename=')) {
      const match = disposition.match(/filename=["']?([^"';]+)["']?/);
      if (match && match[1]) filename = match[1];
    }

    const blobUrl = window.URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = blobUrl;
    link.download = filename;
    document.body.appendChild(link);
    link.click();

    setTimeout(() => {
      link.remove();
      window.URL.revokeObjectURL(blobUrl);
    }, 1000);

    showToast('PDF Report downloaded successfully!', 'success');
  } catch (err) {
    console.error('[PDF Download Failure]', err);
    showToast(err.message || 'Unable to generate PDF. Please try again.', 'danger');
  }
}

window.downloadReportPDF = downloadReportPDF;

// Mobile BFCache & History State Handler (Ensures auto-load on back/forward/logout)
window.addEventListener('pageshow', (event) => {
  const currentPath = window.location.pathname.split('/').pop() || 'index.html';
  const isAuthPage = currentPath === 'login.html' || currentPath === 'register.html';
  const token = getToken();

  if (!token && !isAuthPage && currentPath !== 'index.html') {
    window.location.replace('login.html?t=' + Date.now());
  } else if (token && isAuthPage) {
    window.location.replace('dashboard.html?t=' + Date.now());
  }
});

// Initialize Sidebar Active Links & User Info
document.addEventListener('DOMContentLoaded', () => {
  const currentUser = getUser();

  const nameEl = document.getElementById('user-display-name');
  const roleEl = document.getElementById('user-display-role');
  if (nameEl) nameEl.textContent = currentUser.username || 'SecAnalyst';
  if (roleEl) roleEl.textContent = (currentUser.role || 'user').toUpperCase();

  const sidebarUser = document.querySelector('.sidebar-user');
  if (sidebarUser && !document.querySelector('.dev-credit-tag')) {
    const devTag = document.createElement('div');
    devTag.className = 'dev-credit-tag';
    devTag.style.cssText = 'font-size: 11px; color: var(--cyan); margin-top: 10px; padding: 6px 10px; background: rgba(0,212,255,0.08); border-radius: 6px; border: 1px solid rgba(0,212,255,0.2); width: 100%; text-align: center; font-weight: 500;';
    devTag.innerHTML = '<i class="fas fa-shield-halved"></i> Architect: <strong>Vishva</strong>';
    sidebarUser.parentNode.insertBefore(devTag, sidebarUser.nextSibling);
  }

  const currentPath = window.location.pathname.split('/').pop() || 'index.html';
  document.querySelectorAll('.sidebar-nav li a').forEach(a => {
    if (a.getAttribute('href') === currentPath) {
      a.parentElement.classList.add('active');
    }
  });

  const topbar = document.querySelector('.topbar');
  if (topbar) {
    if (!document.querySelector('.system-status-pill')) {
      const statusPill = document.createElement('div');
      statusPill.className = 'system-status-pill';
      statusPill.innerHTML = '<span class="pulse-dot"></span> <span>AI SHIELD: ACTIVE</span>';
      topbar.querySelector('.topbar-title')?.appendChild(statusPill);
    }

    let toggleBtn = document.querySelector('.mobile-nav-toggle');
    if (!toggleBtn) {
      toggleBtn = document.createElement('button');
      toggleBtn.className = 'mobile-nav-toggle btn btn-secondary';
      toggleBtn.style.marginRight = '12px';
      toggleBtn.style.padding = '8px 12px';
      toggleBtn.innerHTML = '<i class="fas fa-bars"></i>';
      topbar.insertBefore(toggleBtn, topbar.firstChild);
    }
    
    const sidebar = document.querySelector('.sidebar');
    let overlay = document.querySelector('.sidebar-overlay');
    
    if (sidebar && !overlay) {
      overlay = document.createElement('div');
      overlay.className = 'sidebar-overlay';
      document.body.appendChild(overlay);
    }

    if (sidebar && toggleBtn && overlay) {
      const newToggle = toggleBtn.cloneNode(true);
      if(toggleBtn.parentNode) toggleBtn.parentNode.replaceChild(newToggle, toggleBtn);
      
      const toggleSidebar = () => {
        const isActive = sidebar.classList.contains('active');
        if (isActive) {
          sidebar.classList.remove('active');
          overlay.classList.remove('active');
        } else {
          sidebar.classList.add('active');
          overlay.classList.add('active');
        }
      };

      newToggle.addEventListener('click', toggleSidebar);
      overlay.addEventListener('click', toggleSidebar);
    }
  }

  // Logout button binder (Mobile & Desktop Anti-Cache Handler)
  const logoutBtn = document.getElementById('logout-btn');
  if (logoutBtn) {
    logoutBtn.addEventListener('click', (e) => {
      e.preventDefault();
      removeToken();
      localStorage.removeItem('cybershield_user');
      sessionStorage.removeItem('cybershield_user');
      showToast('Logged out successfully', 'success');
      setTimeout(() => {
        window.location.replace('login.html?logout=' + Date.now());
      }, 150);
    });
  }
});
