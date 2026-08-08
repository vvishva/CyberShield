/**
 * CyberShield - Main Application Core & Global Utilities
 */

// Auto-detect: local development uses /api, production uses full Render URL
const API_BASE = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'
  ? '/api'
  : 'https://cybershield-backend-uhwn.onrender.com/api';

// Toast Notification Manager
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
  }, 4000);
}

// Token & Session Storage Helpers
function getToken() {
  return localStorage.getItem('cybershield_token') || sessionStorage.getItem('cybershield_token');
}

function setToken(token, remember = false) {
  if (remember) {
    localStorage.setItem('cybershield_token', token);
  } else {
    sessionStorage.setItem('cybershield_token', token);
  }
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
  return { username: 'Guest User', email: 'guest@cybershield.io', role: 'user' };
}

function setUser(user, remember = false) {
  const str = JSON.stringify(user);
  if (remember) {
    localStorage.setItem('cybershield_user', str);
  } else {
    sessionStorage.setItem('cybershield_user', str);
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

// Initialize Sidebar Active Links & User Info
document.addEventListener('DOMContentLoaded', () => {
  const currentUser = getUser();
  
  // Update sidebar user details
  const nameEl = document.getElementById('user-display-name');
  const roleEl = document.getElementById('user-display-role');
  if (nameEl) nameEl.textContent = currentUser.username || 'SecAnalyst';
  if (roleEl) roleEl.textContent = (currentUser.role || 'user').toUpperCase();

  // Active page highlight
  const currentPath = window.location.pathname.split('/').pop() || 'index.html';
  document.querySelectorAll('.sidebar-nav li a').forEach(a => {
    if (a.getAttribute('href') === currentPath) {
      a.parentElement.classList.add('active');
    }
  });

  // Mobile navigation hamburger menu toggle
  const topbar = document.querySelector('.topbar');
  if (topbar && !document.querySelector('.mobile-nav-toggle')) {
    const toggleBtn = document.createElement('button');
    toggleBtn.className = 'mobile-nav-toggle btn btn-secondary';
    toggleBtn.style.marginRight = '12px';
    toggleBtn.style.padding = '8px 12px';
    toggleBtn.innerHTML = '<i class="fas fa-bars"></i>';
    topbar.insertBefore(toggleBtn, topbar.firstChild);

    const sidebar = document.querySelector('.sidebar');
    toggleBtn.addEventListener('click', () => {
      if (sidebar) sidebar.classList.toggle('active');
    });

    // Close sidebar when clicking outside on mobile
    document.addEventListener('click', (e) => {
      if (sidebar && sidebar.classList.contains('active')) {
        if (!sidebar.contains(e.target) && !toggleBtn.contains(e.target)) {
          sidebar.classList.remove('active');
        }
      }
    });
  }

  // Logout button binder
  const logoutBtn = document.getElementById('logout-btn');
  if (logoutBtn) {
    logoutBtn.addEventListener('click', (e) => {
      e.preventDefault();
      removeToken();
      localStorage.removeItem('cybershield_user');
      sessionStorage.removeItem('cybershield_user');
      showToast('Logged out successfully', 'success');
      setTimeout(() => window.location.href = 'login.html', 800);
    });
  }
});
