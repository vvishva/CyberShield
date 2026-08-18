/**
 * CyberShield — AI Security Copilot & SOC Analyst Frontend Engine
 *
 * Renders the CyberShield Enterprise SOC AI Assistant with multi-turn conversation memory,
 * intelligent intent routing, responsive mobile chat layout, and Android virtual keyboard resilience.
 */

(function () {
  let isCopilotOpen = false;
  let isSending = false;
  let conversationHistory = [];
  let lastFailedPrompt = null;

  function getCurrentPageContext() {
    const path = (window.location.pathname.split('/').pop() || 'index.html').toLowerCase();
    if (path === 'dashboard.html' || path === 'dashboard' || path === '') return 'dashboard';
    if (path.includes('scanner')) return 'scanner';
    if (path.includes('history')) return 'scan_history';
    if (path.includes('reports')) return 'audit_reports';
    if (path.includes('password')) return 'password_analyzer';
    if (path.includes('threat')) return 'threat_intelligence';
    if (path.includes('admin')) return 'admin_panel';
    if (path.includes('profile')) return 'user_profile';
    if (path.includes('settings')) return 'settings';
    if (path.includes('notifications')) return 'notifications';
    if (path.includes('monitor')) return 'continuous_monitoring';
    if (path.includes('attack-surface')) return 'attack_surface';
    if (path.includes('vulnerabilit')) return 'vulnerabilities';
    if (path.includes('investigation')) return 'investigation';
    return 'general';
  }

  function initAICopilotUI() {
    if (document.getElementById('ai-copilot-container')) return;

    // 1. Create Floating AI Action Button
    const fab = document.createElement('button');
    fab.id = 'ai-copilot-fab';
    fab.className = 'ai-copilot-fab';
    fab.setAttribute('aria-label', 'Open CyberShield AI Security Copilot');
    fab.title = 'CyberShield AI Security Copilot';
    fab.innerHTML = `
      <div class="ai-fab-icon"><i class="fas fa-robot"></i></div>
      <span class="ai-fab-text">AI Security Copilot</span>
      <span class="ai-online-pulse"></span>
    `;
    document.body.appendChild(fab);

    // 2. Create AI Drawer Container
    const drawer = document.createElement('div');
    drawer.id = 'ai-copilot-container';
    drawer.className = 'ai-copilot-drawer';
    drawer.setAttribute('role', 'dialog');
    drawer.setAttribute('aria-label', 'CyberShield AI Security Copilot Chat');
    drawer.innerHTML = `
      <div class="ai-copilot-header">
        <div class="ai-header-title">
          <div class="ai-avatar-icon"><i class="fas fa-shield-halved"></i></div>
          <div>
            <h3>CyberShield AI Copilot</h3>
            <div class="ai-status-indicator"><span class="pulse-dot-green"></span> AI Engine Online</div>
          </div>
        </div>
        <div class="ai-header-controls">
          <button class="ai-control-btn" id="ai-clear-btn" title="Clear Conversation" aria-label="Clear Conversation"><i class="fas fa-trash-can"></i></button>
          <button class="ai-control-btn" id="ai-close-btn" title="Close Copilot" aria-label="Close Copilot"><i class="fas fa-times"></i></button>
        </div>
      </div>

      <div class="ai-copilot-body" id="ai-chat-body">
        <!-- Welcome Screen -->
        <div class="ai-welcome-card" id="ai-welcome-card">
          <div class="ai-welcome-badge"><i class="fas fa-shield-halved"></i> AI SOC Security Analyst</div>
          <h4>CyberShield AI Security Copilot</h4>
          <p class="ai-welcome-sub">Ask any cybersecurity question, analyze live CyberShield security metrics, triage vulnerabilities, or investigate threats.</p>

          <div class="ai-quick-actions-title">QUICK SECURITY ACTIONS:</div>
          <div class="ai-quick-grid">
            <button class="ai-quick-btn" data-action="briefing"><i class="fas fa-list-check"></i> Give Me Today's SOC Briefing</button>
            <button class="ai-quick-btn" data-action="score"><i class="fas fa-chart-line"></i> What Is My Security Score?</button>
            <button class="ai-quick-btn" data-action="threats"><i class="fas fa-triangle-exclamation"></i> Show Active Threats</button>
            <button class="ai-quick-btn" data-action="vuln"><i class="fas fa-bug"></i> Which Vulnerability To Fix First?</button>
            <button class="ai-quick-btn" data-action="soc_concept"><i class="fas fa-shield"></i> What is a SOC?</button>
            <button class="ai-quick-btn" data-action="diff_threat_vuln"><i class="fas fa-scale-balanced"></i> Threat vs Vulnerability</button>
          </div>
        </div>
        <div id="ai-messages-list"></div>
      </div>

      <div class="ai-copilot-footer">
        <form class="ai-input-wrapper" id="ai-chat-form" onsubmit="return false;">
          <textarea id="ai-chat-input" rows="1" placeholder="Ask AI about security, CVEs, threats, SOC..." autocomplete="off" autocorrect="off" autocapitalize="sentences" spellcheck="false"></textarea>
          <button type="submit" id="ai-send-btn" class="btn btn-primary" title="Send Message" aria-label="Send Message">
            <i class="fas fa-paper-plane"></i>
          </button>
        </form>
        <div class="ai-footer-note">Defensive Cybersecurity Assistant • Real-Time SOC Telemetry</div>
      </div>

      <!-- Clear Chat Confirmation Modal Overlay -->
      <div class="ai-confirm-overlay" id="ai-clear-confirm" style="display:none;">
        <div class="ai-confirm-box">
          <div class="ai-confirm-icon"><i class="fas fa-triangle-exclamation text-warning"></i></div>
          <h4>Clear Conversation?</h4>
          <p>This will remove your current chat messages with the AI Copilot.</p>
          <div class="ai-confirm-actions">
            <button class="btn btn-secondary btn-sm" id="btn-cancel-clear">Cancel</button>
            <button class="btn btn-danger btn-sm" id="btn-confirm-clear">Clear Chat</button>
          </div>
        </div>
      </div>
    `;
    document.body.appendChild(drawer);

    // Event Listeners
    fab.addEventListener('click', toggleCopilot);
    document.getElementById('ai-close-btn').addEventListener('click', toggleCopilot);
    
    // Clear Chat with Confirmation Modal
    const clearBtn = document.getElementById('ai-clear-btn');
    const confirmOverlay = document.getElementById('ai-clear-confirm');
    const cancelClearBtn = document.getElementById('btn-cancel-clear');
    const confirmClearBtn = document.getElementById('btn-confirm-clear');

    if (clearBtn && confirmOverlay) {
      clearBtn.addEventListener('click', () => {
        confirmOverlay.style.display = 'flex';
      });
    }
    if (cancelClearBtn && confirmOverlay) {
      cancelClearBtn.addEventListener('click', () => {
        confirmOverlay.style.display = 'none';
      });
    }
    if (confirmClearBtn && confirmOverlay) {
      confirmClearBtn.addEventListener('click', () => {
        confirmOverlay.style.display = 'none';
        performClearChat();
      });
    }

    // Input & Form Submission
    const chatForm = document.getElementById('ai-chat-form');
    const inputEl = document.getElementById('ai-chat-input');

    if (chatForm) {
      chatForm.addEventListener('submit', (e) => {
        e.preventDefault();
        sendUserMessage();
      });
    }

    if (inputEl) {
      // Auto-expand textarea height
      inputEl.addEventListener('input', function () {
        this.style.height = 'auto';
        this.style.height = Math.min(this.scrollHeight, 120) + 'px';
      });

      // Desktop Enter to send (Shift+Enter for newline)
      inputEl.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' && !e.shiftKey && window.innerWidth > 768) {
          e.preventDefault();
          sendUserMessage();
        }
      });
    }

    // Quick Action Listeners
    drawer.querySelectorAll('.ai-quick-btn').forEach(btn => {
      btn.addEventListener('click', () => handleQuickAction(btn.dataset.action));
    });

    // Setup Visual Viewport listener for Android Virtual Keyboard
    setupVisualViewportHandling();
  }

  function setupVisualViewportHandling() {
    if (!window.visualViewport) return;

    const drawer = document.getElementById('ai-copilot-container');
    const handleViewportChange = () => {
      if (!isCopilotOpen || window.innerWidth > 768 || !drawer) return;
      
      const vv = window.visualViewport;
      drawer.style.height = `${vv.height}px`;
      drawer.style.top = `${vv.offsetTop}px`;
      
      // Keep active element and latest message visible
      setTimeout(scrollToBottom, 50);
    };

    window.visualViewport.addEventListener('resize', handleViewportChange);
    window.visualViewport.addEventListener('scroll', handleViewportChange);
  }

  function toggleCopilot() {
    const drawer = document.getElementById('ai-copilot-container');
    const fab = document.getElementById('ai-copilot-fab');
    if (!drawer) return;

    isCopilotOpen = !isCopilotOpen;
    if (isCopilotOpen) {
      drawer.classList.add('open');
      fab?.classList.add('active');
      if (window.innerWidth <= 768) {
        document.body.classList.add('ai-copilot-open');
        if (window.visualViewport) {
          drawer.style.height = `${window.visualViewport.height}px`;
          drawer.style.top = `${window.visualViewport.offsetTop}px`;
        }
      }
      setTimeout(() => {
        const inputEl = document.getElementById('ai-chat-input');
        if (inputEl && window.innerWidth > 768) inputEl.focus();
        scrollToBottom();
      }, 200);
    } else {
      drawer.classList.remove('open');
      fab?.classList.remove('active');
      document.body.classList.remove('ai-copilot-open');
      if (drawer) {
        drawer.style.height = '';
        drawer.style.top = '';
      }
    }
  }

  function openCopilotWithPrompt(promptText) {
    if (!isCopilotOpen) toggleCopilot();
    const inputEl = document.getElementById('ai-chat-input');
    if (inputEl) {
      inputEl.value = promptText;
      sendUserMessage();
    }
  }

  function performClearChat() {
    conversationHistory = [];
    const list = document.getElementById('ai-messages-list');
    if (list) list.innerHTML = '';
    const welcome = document.getElementById('ai-welcome-card');
    if (welcome) welcome.style.display = 'block';
    if (typeof showToast === 'function') showToast('Conversation cleared.', 'info');
  }

  async function handleQuickAction(actionType) {
    const welcome = document.getElementById('ai-welcome-card');
    if (welcome) welcome.style.display = 'none';

    if (actionType === 'briefing') {
      appendUserMessage("Give me today's SOC Briefing");
      await executeAIRequest('/ai/briefing', 'GET');
    } else if (actionType === 'score') {
      appendUserMessage("What is my current security score?");
      await executeAIRequest('/ai/chat', 'POST', { prompt: "What is my current security score?", history: conversationHistory.slice(-8), pageContext: getCurrentPageContext() });
    } else if (actionType === 'threats') {
      appendUserMessage("Show active threats");
      await executeAIRequest('/ai/chat', 'POST', { prompt: "Show active threats", history: conversationHistory.slice(-8), pageContext: getCurrentPageContext() });
    } else if (actionType === 'vuln') {
      appendUserMessage("Which vulnerability should I prioritize?");
      await executeAIRequest('/ai/chat', 'POST', { prompt: "Which vulnerability should I prioritize?", history: conversationHistory.slice(-8), pageContext: getCurrentPageContext() });
    } else if (actionType === 'soc_concept') {
      appendUserMessage("What is a SOC?");
      await executeAIRequest('/ai/chat', 'POST', { prompt: "What is a SOC?", history: conversationHistory.slice(-8), pageContext: getCurrentPageContext() });
    } else if (actionType === 'diff_threat_vuln') {
      appendUserMessage("What is the difference between a threat and a vulnerability?");
      await executeAIRequest('/ai/chat', 'POST', { prompt: "What is the difference between a threat and a vulnerability?", history: conversationHistory.slice(-8), pageContext: getCurrentPageContext() });
    }
  }

  async function sendUserMessage() {
    if (isSending) return;

    const inputEl = document.getElementById('ai-chat-input');
    const prompt = inputEl?.value?.trim();
    if (!prompt) return;

    inputEl.value = '';
    inputEl.style.height = 'auto';

    const welcome = document.getElementById('ai-welcome-card');
    if (welcome) welcome.style.display = 'none';

    appendUserMessage(prompt);
    lastFailedPrompt = prompt;

    await executeAIRequest('/ai/chat', 'POST', {
      prompt,
      history: conversationHistory.slice(-8),
      pageContext: getCurrentPageContext()
    });
  }

  function appendUserMessage(text) {
    conversationHistory.push({ role: 'user', content: text });
    if (conversationHistory.length > 16) conversationHistory.shift();

    const list = document.getElementById('ai-messages-list');
    if (!list) return;

    const time = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    const msgEl = document.createElement('div');
    msgEl.className = 'ai-message user-msg';
    msgEl.innerHTML = `
      <div class="msg-bubble">${escapeHtml(text)}</div>
      <div class="msg-time">${time}</div>
    `;
    list.appendChild(msgEl);
    scrollToBottom(true);
  }

  function appendTypingIndicator() {
    const list = document.getElementById('ai-messages-list');
    if (!list) return null;

    const id = 'typing-' + Date.now();
    const msgEl = document.createElement('div');
    msgEl.id = id;
    msgEl.className = 'ai-message bot-msg typing-msg';
    msgEl.innerHTML = `
      <div class="msg-avatar"><i class="fas fa-brain fa-pulse"></i></div>
      <div class="msg-bubble">
        <span class="ai-scanning-text">CyberShield AI is analyzing...</span>
        <span class="typing-dots"><span>.</span><span>.</span><span>.</span></span>
      </div>
    `;
    list.appendChild(msgEl);
    scrollToBottom(true);
    return id;
  }

  function removeTypingIndicator(id) {
    const el = document.getElementById(id);
    if (el) el.remove();
  }

  async function executeAIRequest(endpoint, method = 'POST', body = null) {
    if (isSending) return;
    isSending = true;
    
    const sendBtn = document.getElementById('ai-send-btn');
    if (sendBtn) {
      sendBtn.disabled = true;
      sendBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i>';
    }

    const typingId = appendTypingIndicator();

    try {
      const data = await apiRequest(endpoint, method, body);
      removeTypingIndicator(typingId);

      if (data.success && data.data) {
        const responseText = data.data.response || data.data.briefing || data.data.analysis || data.data.explanation || data.data.investigation || data.data.report;
        if (responseText) {
          conversationHistory.push({ role: 'assistant', content: responseText });
          if (conversationHistory.length > 16) conversationHistory.shift();
          appendBotMessage(responseText);
        } else {
          appendBotMessage("Security analysis complete. No critical alerts reported.");
        }
      } else {
        appendBotErrorMessage(data.error || "Unable to reach the AI Security engine right now. Please try again.");
      }
    } catch (err) {
      removeTypingIndicator(typingId);
      const errMsg = err.message?.includes('429')
        ? "AI Copilot rate limit reached. Please wait a few moments before making another request."
        : "I couldn't reach the AI engine right now. Please check your connection and try again.";
      appendBotErrorMessage(errMsg);
    } finally {
      isSending = false;
      if (sendBtn) {
        sendBtn.disabled = false;
        sendBtn.innerHTML = '<i class="fas fa-paper-plane"></i>';
      }
    }
  }

  function appendBotErrorMessage(errorText) {
    const list = document.getElementById('ai-messages-list');
    if (!list) return;

    const time = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    const msgEl = document.createElement('div');
    msgEl.className = 'ai-message bot-msg error-msg';
    msgEl.innerHTML = `
      <div class="msg-avatar"><i class="fas fa-triangle-exclamation text-danger"></i></div>
      <div class="msg-bubble-wrapper">
        <div class="msg-bubble" style="border-color:rgba(239,68,68,0.3); background:rgba(239,68,68,0.06);">
          <p style="margin:0 0 8px 0; color:#fca5a5;">${escapeHtml(errorText)}</p>
          <button class="btn btn-secondary btn-sm btn-retry-ai" style="font-size:11px; padding:3px 8px;">
            <i class="fas fa-rotate"></i> Retry
          </button>
        </div>
        <div class="msg-actions"><span class="msg-time">${time}</span></div>
      </div>
    `;

    const retryBtn = msgEl.querySelector('.btn-retry-ai');
    if (retryBtn) {
      retryBtn.addEventListener('click', () => {
        msgEl.remove();
        if (lastFailedPrompt) {
          executeAIRequest('/ai/chat', 'POST', {
            prompt: lastFailedPrompt,
            history: conversationHistory.slice(-8),
            pageContext: getCurrentPageContext()
          });
        }
      });
    }

    list.appendChild(msgEl);
    scrollToBottom(true);
  }

  function appendBotMessage(markdownText) {
    const list = document.getElementById('ai-messages-list');
    if (!list) return;

    const time = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    const formattedHTML = formatMarkdownResponse(markdownText);

    const msgEl = document.createElement('div');
    msgEl.className = 'ai-message bot-msg';
    msgEl.innerHTML = `
      <div class="msg-avatar"><i class="fas fa-shield-halved"></i></div>
      <div class="msg-bubble-wrapper">
        <div class="msg-bubble markdown-body">${formattedHTML}</div>
        <div class="msg-actions">
          <span class="msg-time">${time}</span>
          <button class="msg-copy-btn" title="Copy Response" aria-label="Copy Response"><i class="fas fa-copy"></i></button>
        </div>
      </div>
    `;

    const copyBtn = msgEl.querySelector('.msg-copy-btn');
    if (copyBtn) {
      copyBtn.addEventListener('click', () => {
        navigator.clipboard.writeText(markdownText);
        if (typeof showToast === 'function') showToast('AI analysis copied to clipboard', 'info');
      });
    }

    list.appendChild(msgEl);
    scrollToBottom();
  }

  function formatMarkdownResponse(text) {
    if (!text) return '';
    let html = escapeHtml(text);

    // Headers
    html = html.replace(/#### (.*?)\n/g, '<h5 class="ai-res-h4">$1</h5>');
    html = html.replace(/### (.*?)\n/g, '<h4 class="ai-res-h3">$1</h4>');
    html = html.replace(/## (.*?)\n/g, '<h3 class="ai-res-h2">$1</h3>');
    html = html.replace(/# (.*?)\n/g, '<h2 class="ai-res-h1">$1</h2>');

    // Bold & Code
    html = html.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');
    html = html.replace(/`([^`]+)`/g, '<code>$1</code>');

    // Lists
    html = html.replace(/^- (.*?)$/gm, '<li>$1</li>');
    html = html.replace(/(<li>.*?<\/li>)/gs, '<ul>$1</ul>');

    // Numbered Lists
    html = html.replace(/^\d+\.\s+(.*?)$/gm, '<li>$1</li>');

    // Tables
    html = html.replace(/\|(.+)\|/g, (match) => {
      const cells = match.split('|').filter(c => c.trim() !== '');
      if (cells.some(c => c.includes('---'))) return '';
      return '<tr>' + cells.map(c => `<td>${c.trim()}</td>`).join('') + '</tr>';
    });

    // Newlines
    html = html.replace(/\n\n/g, '<br><br>');
    return html;
  }

  function scrollToBottom(force = false) {
    const body = document.getElementById('ai-chat-body');
    if (!body) return;

    // Check if user is already scrolled up reading older messages
    const isNearBottom = body.scrollHeight - body.scrollTop - body.clientHeight < 120;
    if (force || isNearBottom) {
      body.scrollTop = body.scrollHeight;
    }
  }

  // Expose global formatting helper
  window.formatMarkdownResponse = formatMarkdownResponse;

  // Expose global methods
  window.CyberShieldAI = {
    toggle: toggleCopilot,
    ask: openCopilotWithPrompt
  };

  document.addEventListener('DOMContentLoaded', initAICopilotUI);
})();
