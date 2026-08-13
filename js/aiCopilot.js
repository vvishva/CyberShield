/**
 * CyberShield — AI Security Copilot & SOC Analyst Frontend Engine
 *
 * Renders the CyberShield Enterprise SOC AI Assistant, Context-Aware Quick Actions,
 * AI SOC Briefing, AI Security Score Explainer, and AI Report Generator.
 */

(function () {
  let isCopilotOpen = false;
  let chatHistory = [];

  function getCurrentPageContext() {
    const path = window.location.pathname.split('/').pop() || 'index.html';
    if (path.includes('scanner')) return 'scanner';
    if (path.includes('history')) return 'scan_history';
    if (path.includes('reports')) return 'audit_reports';
    if (path.includes('password')) return 'password_analyzer';
    if (path.includes('threat')) return 'threat_intelligence';
    if (path.includes('admin')) return 'admin_panel';
    if (path.includes('profile')) return 'user_profile';
    return 'dashboard';
  }

  function initAICopilotUI() {
    if (document.getElementById('ai-copilot-container')) return;

    // 1. Create Floating AI Action Button
    const fab = document.createElement('button');
    fab.id = 'ai-copilot-fab';
    fab.className = 'ai-copilot-fab';
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
    drawer.innerHTML = `
      <div class="ai-copilot-header">
        <div class="ai-header-title">
          <div class="ai-avatar-icon"><i class="fas fa-brain"></i></div>
          <div>
            <h3>CyberShield AI Copilot</h3>
            <div class="ai-status-indicator"><span class="pulse-dot-green"></span> AI Engine Online</div>
          </div>
        </div>
        <div class="ai-header-controls">
          <button class="ai-control-btn" id="ai-clear-btn" title="Clear Chat"><i class="fas fa-broom"></i></button>
          <button class="ai-control-btn" id="ai-close-btn" title="Close"><i class="fas fa-times"></i></button>
        </div>
      </div>

      <div class="ai-copilot-body" id="ai-chat-body">
        <!-- Welcome Screen -->
        <div class="ai-welcome-card" id="ai-welcome-card">
          <div class="ai-welcome-badge"><i class="fas fa-shield-halved"></i> AI SOC Security Analyst</div>
          <h4>CyberShield AI Security Copilot</h4>
          <p class="ai-welcome-sub">Your intelligent security analysis assistant. Analyzes live CyberShield security metrics, threats, vulnerabilities, and audit telemetry.</p>

          <div class="ai-quick-actions-title">QUICK SECURITY ACTIONS:</div>
          <div class="ai-quick-grid">
            <button class="ai-quick-btn" data-action="briefing"><i class="fas fa-list-check"></i> Give Me Today's SOC Briefing</button>
            <button class="ai-quick-btn" data-action="score"><i class="fas fa-chart-line"></i> Explain Security Score</button>
            <button class="ai-quick-btn" data-action="scan"><i class="fas fa-magnifying-glass"></i> Analyze Latest Scan</button>
            <button class="ai-quick-btn" data-action="threats"><i class="fas fa-triangle-exclamation"></i> Investigate Active Threats</button>
            <button class="ai-quick-btn" data-action="vuln"><i class="fas fa-bug"></i> Explain Vulnerabilities</button>
            <button class="ai-quick-btn" data-action="surface"><i class="fas fa-network-wired"></i> Analyze Attack Surface</button>
            <button class="ai-quick-btn" data-action="report"><i class="fas fa-file-shield"></i> Generate Security Report</button>
          </div>
        </div>
        <div id="ai-messages-list"></div>
      </div>

      <div class="ai-copilot-footer">
        <div class="ai-input-wrapper">
          <input type="text" id="ai-chat-input" placeholder="Ask AI Copilot about security scores, threats, scans..." autocomplete="off">
          <button id="ai-send-btn" class="btn btn-primary"><i class="fas fa-paper-plane"></i></button>
        </div>
        <div class="ai-footer-note">Defensive Security Analysis • Powered by CyberShield AI</div>
      </div>
    `;
    document.body.appendChild(drawer);

    // Event Listeners
    fab.addEventListener('click', toggleCopilot);
    document.getElementById('ai-close-btn').addEventListener('click', toggleCopilot);
    document.getElementById('ai-clear-btn').addEventListener('click', clearChatHistory);
    document.getElementById('ai-send-btn').addEventListener('click', sendUserMessage);

    const inputEl = document.getElementById('ai-chat-input');
    inputEl.addEventListener('keypress', (e) => {
      if (e.key === 'Enter') sendUserMessage();
    });

    // Quick Action Listeners
    drawer.querySelectorAll('.ai-quick-btn').forEach(btn => {
      btn.addEventListener('click', () => handleQuickAction(btn.dataset.action));
    });

    // Page-specific Context integrations
    integratePageContextAI();
  }

  function toggleCopilot() {
    const drawer = document.getElementById('ai-copilot-container');
    const fab = document.getElementById('ai-copilot-fab');
    if (!drawer) return;

    isCopilotOpen = !isCopilotOpen;
    if (isCopilotOpen) {
      drawer.classList.add('open');
      fab.classList.add('active');
      document.getElementById('ai-chat-input')?.focus();
    } else {
      drawer.classList.remove('open');
      fab.classList.remove('active');
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

  function clearChatHistory() {
    chatHistory = [];
    const list = document.getElementById('ai-messages-list');
    if (list) list.innerHTML = '';
    const welcome = document.getElementById('ai-welcome-card');
    if (welcome) welcome.style.display = 'block';
  }

  async function handleQuickAction(actionType) {
    const welcome = document.getElementById('ai-welcome-card');
    if (welcome) welcome.style.display = 'none';

    if (actionType === 'briefing') {
      appendUserMessage("Give me today's SOC Briefing");
      await executeAIRequest('/ai/briefing', 'GET');
    } else if (actionType === 'score') {
      appendUserMessage("Explain my Security Score and risk breakdown");
      await executeAIRequest('/ai/explain-score', 'POST', {});
    } else if (actionType === 'scan') {
      appendUserMessage("Analyze my latest security scan");
      await executeAIRequest('/ai/explain-scan', 'POST', {});
    } else if (actionType === 'threats') {
      appendUserMessage("Investigate active threats and prioritize remediation");
      await executeAIRequest('/ai/investigate', 'POST', {});
    } else if (actionType === 'vuln') {
      appendUserMessage("Explain detected vulnerabilities and remediation steps");
      await executeAIRequest('/ai/explain-vulnerability', 'POST', {});
    } else if (actionType === 'surface') {
      appendUserMessage("Analyze my attack surface and exposed web assets");
      await executeAIRequest('/ai/chat', 'POST', { prompt: "Analyze my attack surface and exposed web assets", pageContext: getCurrentPageContext() });
    } else if (actionType === 'report') {
      appendUserMessage("Generate AI Security Audit Report");
      await executeAIRequest('/ai/generate-report', 'POST', {});
    }
  }

  const conversationHistory = [];

  async function sendUserMessage() {
    const inputEl = document.getElementById('ai-chat-input');
    const prompt = inputEl?.value?.trim();
    if (!prompt) return;

    inputEl.value = '';
    const welcome = document.getElementById('ai-welcome-card');
    if (welcome) welcome.style.display = 'none';

    appendUserMessage(prompt);
    await executeAIRequest('/ai/chat', 'POST', {
      prompt,
      history: conversationHistory.slice(-10),
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
    scrollToBottom();
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
    scrollToBottom();
    return id;
  }

  function removeTypingIndicator(id) {
    const el = document.getElementById(id);
    if (el) el.remove();
  }

  async function executeAIRequest(endpoint, method = 'POST', body = null) {
    const typingId = appendTypingIndicator();

    try {
      const data = await apiRequest(endpoint, method, body);
      removeTypingIndicator(typingId);

      if (data.success && data.data) {
        const responseText = data.data.response || data.data.briefing || data.data.analysis || data.data.explanation || data.data.investigation || data.data.report;
        if (responseText) {
          conversationHistory.push({ role: 'assistant', content: responseText });
          if (conversationHistory.length > 16) conversationHistory.shift();
        }
        appendBotMessage(responseText || "Analysis complete.");
      } else {
        appendBotMessage(data.error || "I don't have enough current CyberShield data to answer this accurately.");
      }
    } catch (err) {
      removeTypingIndicator(typingId);
      const errMsg = err.message?.includes('429')
        ? "AI Copilot rate limit reached. Please wait a few moments before making another request."
        : "AI Security Copilot is temporarily unavailable. Please verify your connection or try again.";
      appendBotMessage(`❌ ${errMsg}`);
    }
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
          <button class="msg-copy-btn" title="Copy Response"><i class="fas fa-copy"></i></button>
        </div>
      </div>
    `;

    const copyBtn = msgEl.querySelector('.msg-copy-btn');
    if (copyBtn) {
      copyBtn.addEventListener('click', () => {
        navigator.clipboard.writeText(markdownText);
        showToast('AI analysis copied to clipboard', 'info');
      });
    }

    list.appendChild(msgEl);
    scrollToBottom();
  }

  function formatMarkdownResponse(text) {
    if (!text) return '';
    let html = escapeHtml(text);

    // Formatter headers
    html = html.replace(/### (.*?)\n/g, '<h4 class="ai-res-h3">$1</h4>');
    html = html.replace(/## (.*?)\n/g, '<h3 class="ai-res-h2">$1</h3>');
    html = html.replace(/# (.*?)\n/g, '<h2 class="ai-res-h1">$1</h2>');

    // Bold & Code
    html = html.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');
    html = html.replace(/`([^`]+)`/g, '<code>$1</code>');

    // Bullets
    html = html.replace(/^- (.*?)$/gm, '<li>$1</li>');
    html = html.replace(/(<li>.*?<\/li>)/gs, '<ul>$1</ul>');

    // Security score badges
    html = html.replace(/SECURITY SCORE:\s*`?(\d+\/\d+)`?/gi, '<div class="ai-score-pill"><i class="fas fa-shield-cat"></i> SECURITY SCORE: <strong>$1</strong></div>');
    html = html.replace(/Risk Level:\s*`?([^`\n]+)`?/gi, '<span class="badge badge-warning">Risk Level: $1</span>');

    // Newlines
    html = html.replace(/\n\n/g, '<br><br>');
    return html;
  }

  function scrollToBottom() {
    const body = document.getElementById('ai-chat-body');
    if (body) body.scrollTop = body.scrollHeight;
  }

  // Page Context Integrations
  function integratePageContextAI() {
    const page = getCurrentPageContext();

    // 1. Dashboard AI Briefing Card Insertion
    if (page === 'dashboard') {
      const contentBody = document.querySelector('.content-body');
      if (contentBody && !document.getElementById('dashboard-ai-briefing-card')) {
        const briefingCard = document.createElement('div');
        briefingCard.id = 'dashboard-ai-briefing-card';
        briefingCard.className = 'glass-card ai-dashboard-banner';
        briefingCard.innerHTML = `
          <div class="ai-banner-header">
            <div class="ai-banner-title"><i class="fas fa-brain text-cyan"></i> CyberShield AI SOC Security Briefing</div>
            <button class="btn btn-secondary btn-sm" id="btn-refresh-briefing"><i class="fas fa-rotate"></i> Refresh AI Briefing</button>
          </div>
          <div class="ai-banner-content" id="ai-briefing-text">
            <div class="ai-inline-loading"><i class="fas fa-spinner fa-spin"></i> Generating real-time AI security briefing...</div>
          </div>
        `;
        contentBody.prepend(briefingCard);

        document.getElementById('btn-refresh-briefing')?.addEventListener('click', loadDashboardAIBriefing);
        loadDashboardAIBriefing();
      }
    }
  }

  async function loadDashboardAIBriefing() {
    const target = document.getElementById('ai-briefing-text');
    if (!target) return;

    target.innerHTML = '<div class="ai-inline-loading"><i class="fas fa-spinner fa-spin"></i> Analyzing live CyberShield SOC telemetry...</div>';

    try {
      const data = await apiRequest('/ai/briefing', 'GET');
      if (data.success && data.data?.briefing) {
        target.innerHTML = formatMarkdownResponse(data.data.briefing);
      } else {
        target.innerHTML = '<p class="text-muted">AI Briefing telemetry loaded. Click <strong>AI Security Copilot</strong> for full breakdown.</p>';
      }
    } catch (e) {
      target.innerHTML = '<p class="text-muted"><i class="fas fa-shield-halved text-cyan"></i> AI Shield Active. All endpoints monitored continuously.</p>';
    }
  }

  // Expose global methods
  window.CyberShieldAI = {
    toggle: toggleCopilot,
    ask: openCopilotWithPrompt
  };

  document.addEventListener('DOMContentLoaded', initAICopilotUI);
})();
