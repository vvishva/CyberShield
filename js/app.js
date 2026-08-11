/**
 * CyberShield - Main Application Core & Global Utilities
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
  // In-app Toast
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

  // Native Browser Notification
  if ('Notification' in window) {
    if (Notification.permission === 'granted') {
      new Notification('CyberShield AI', {
        body: message,
        icon: '/images/favicon.png' // assuming there's an icon, or fallback to default
      });
    } else if (Notification.permission !== 'denied') {
      Notification.requestPermission().then(permission => {
        if (permission === 'granted') {
          new Notification('CyberShield AI', { body: message });
        }
      });
    }
  }
}

// HTML Escape utility (used globally across JS files)
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

// Authentication Guard
function requireAuth() {
  const token = getToken();
  if (!token) {
    window.location.href = 'login.html';
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

  // Update sidebar user details & developer credit badge
  const nameEl = document.getElementById('user-display-name');
  const roleEl = document.getElementById('user-display-role');
  if (nameEl) nameEl.textContent = currentUser.username || 'SecAnalyst';
  if (roleEl) roleEl.textContent = (currentUser.role || 'user').toUpperCase();

  // Inject Developer Credit Badge (Vishva) into Sidebar
  const sidebarUser = document.querySelector('.sidebar-user');
  if (sidebarUser && !document.querySelector('.dev-credit-tag')) {
    const devTag = document.createElement('div');
    devTag.className = 'dev-credit-tag';
    devTag.style.cssText = 'font-size: 11px; color: var(--cyan); margin-top: 10px; padding: 6px 10px; background: rgba(0,212,255,0.08); border-radius: 6px; border: 1px solid rgba(0,212,255,0.2); width: 100%; text-align: center; font-weight: 500;';
    devTag.innerHTML = '<i class="fas fa-shield-halved"></i> Architect: <strong>Vishva</strong>';
    sidebarUser.parentNode.insertBefore(devTag, sidebarUser.nextSibling);
  }

  // Active page highlight
  const currentPath = window.location.pathname.split('/').pop() || 'index.html';
  document.querySelectorAll('.sidebar-nav li a').forEach(a => {
    if (a.getAttribute('href') === currentPath) {
      a.parentElement.classList.add('active');
    }
  });

  // Inject System Status Indicator & Mobile Hamburger Toggle into Topbar
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
      // Remove old listeners by cloning (if re-init occurs)
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

  // Inject Global CyberBot AI Assistant Widget
  initCyberBotAI();

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

// Interactive CyberShield AI Security Copilot Handler
function initCyberBotAI() {
  if (document.getElementById('cyberbot-fab')) return;

  const fab = document.createElement('button');
  fab.id = 'cyberbot-fab';
  fab.title = 'CyberShield AI Security Copilot';
  fab.innerHTML = '<i class="fas fa-brain"></i>';
  document.body.appendChild(fab);

  const modal = document.createElement('div');
  modal.id = 'cyberbot-modal';
  modal.innerHTML = `
    <div class="cyberbot-header">
      <div style="display: flex; align-items: center; gap: 10px;">
        <i class="fas fa-brain" style="color: var(--cyan); font-size: 20px;"></i>
        <div>
          <h4 style="font-size: 14px; font-weight: 700; margin: 0;">CyberShield AI Security Copilot</h4>
          <span style="font-size: 11px; color: var(--green);">● Active SOC Intelligence</span>
        </div>
      </div>
      <button id="cyberbot-close" style="background: none; border: none; color: var(--text-muted); cursor: pointer; font-size: 16px;"><i class="fas fa-times"></i></button>
    </div>
    <div class="cyberbot-messages" id="cyberbot-messages">
      <div class="chat-msg bot" id="copilot-initial-msg">
        👋 Welcome to <strong>CyberShield AI Security Copilot</strong>. I am analyzing your real-time SOC command telemetry...
      </div>
    </div>
    <div class="cyberbot-suggestions" id="cyberbot-suggestions"></div>
    <div class="cyberbot-input-area">
      <input type="text" id="cyberbot-input" class="form-control" placeholder="Ask Copilot for analysis, investigation, or guidance..." style="font-size: 13px;">
      <button id="cyberbot-send" class="btn btn-primary" style="padding: 8px 14px;"><i class="fas fa-paper-plane"></i></button>
    </div>
  `;
  document.body.appendChild(modal);

  fab.addEventListener('click', () => {
    modal.classList.toggle('active');
    loadCopilotContext();
  });
  document.getElementById('cyberbot-close').addEventListener('click', () => modal.classList.remove('active'));

  const sendBtn = document.getElementById('cyberbot-send');
  const inputEl = document.getElementById('cyberbot-input');
  const msgContainer = document.getElementById('cyberbot-messages');
  const suggestionsEl = document.getElementById('cyberbot-suggestions');

  async function loadCopilotContext() {
    const initMsg = document.getElementById('copilot-initial-msg');
    if (!initMsg) return;

    try {
      const stats = await apiRequest('/scan/stats');
      if (stats.success && stats.data) {
        const threats = stats.data.threatsDetected || 0;
        const score = stats.data.avgSecurityScore || 100;
        initMsg.innerHTML = `
          🛡️ <strong>CyberShield AI Copilot Briefing</strong>:<br>
          • <strong>Active Threats</strong>: ${threats}<br>
          • <strong>Average Security Score</strong>: ${score}/100<br><br>
          Ask me to analyze a specific target, investigate vulnerabilities, or recommend mitigation steps!
        `;
      }
    } catch(e) {
      initMsg.innerHTML = `👋 Hello! I am <strong>CyberShield AI Security Copilot</strong>. Ask me to scan a target, evaluate security headers, test a password, or investigate active threats!`;
    }
  }

  const SUGGESTIONS = [
    'Investigate highest threat',
    'Scan https://example.com',
    'Evaluate security headers',
    'Check password strength',
    'View threat report'
  ];

  function renderSuggestions() {
    if (!suggestionsEl) return;
    suggestionsEl.innerHTML = SUGGESTIONS
      .map(s => `<button class="cyberbot-chip" data-text="${s.replace(/"/g, '&quot;')}">${s}</button>`)
      .join('');
    suggestionsEl.querySelectorAll('.cyberbot-chip').forEach(chip => {
      chip.addEventListener('click', () => {
        inputEl.value = chip.dataset.text;
        handleSend();
      });
    });
  }

  async function handleSend() {
    const text = inputEl.value.trim();
    if (!text) return;

    // User Message
    const userMsg = document.createElement('div');
    userMsg.className = 'chat-msg user';
    userMsg.textContent = text;
    msgContainer.appendChild(userMsg);
    inputEl.value = '';
    if (suggestionsEl) suggestionsEl.innerHTML = '';
    msgContainer.scrollTop = msgContainer.scrollHeight;

    // Bot Typing Indicator
    const typingMsg = document.createElement('div');
    typingMsg.className = 'chat-msg bot';
    typingMsg.innerHTML = '<span class="pulse-dot"></span> <em>Copilot is evaluating security telemetry...</em>';
    msgContainer.appendChild(typingMsg);
    msgContainer.scrollTop = msgContainer.scrollHeight;

    try {
      const data = await apiRequest('/copilot/chat', 'POST', { message: text });
      let replyHtml = data.reply || 'Analysis complete.';
      
      // Inject quick action buttons if reply suggests investigation
      if (text.toLowerCase().includes('report') || replyHtml.toLowerCase().includes('report')) {
        replyHtml += `<div style="margin-top:10px;"><a href="reports.html" class="btn btn-secondary btn-sm"><i class="fas fa-file-pdf"></i> View Reports</a></div>`;
      } else if (text.toLowerCase().includes('scan') || text.toLowerCase().includes('investigate')) {
        replyHtml += `<div style="margin-top:10px;"><a href="scanner.html" class="btn btn-primary btn-sm"><i class="fas fa-search"></i> Open Security Scanner</a></div>`;
      }

      typingMsg.innerHTML = replyHtml;
    } catch(err) {
      typingMsg.innerHTML = `<span style="color:var(--red);">⚠️ ${err.message}. Please check your connection.</span>`;
    }

    renderSuggestions();
    msgContainer.scrollTop = msgContainer.scrollHeight;
  }

  renderSuggestions();
  sendBtn.addEventListener('click', handleSend);
  inputEl.addEventListener('keypress', (e) => { if (e.key === 'Enter') handleSend(); });
}
