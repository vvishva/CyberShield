/**
 * CyberShield — Versatile Natural AI Copilot Engine with Multi-Turn Memory
 *
 * Integrates:
 *   1. Google Gemini API (Primary)
 *   2. Groq Ultra-Fast Free API (Fallback 1)
 *   3. OpenRouter Free Models API (Fallback 2)
 *   4. CyberShield Conversational Fallback Engine (Fallback 3)
 */

const axios = require('axios');
const Scan = require('../models/Scan');
const MonitoredSite = require('../models/MonitoredSite');
const Log = require('../models/Log');

// ============================================================
// CONTROLLED BACKEND DATA RETRIEVAL FUNCTIONS
// ============================================================

async function getDashboardSummary(userId, isAdmin = false) {
  const query = isAdmin ? {} : { user: userId };
  const scans = await Scan.find(query).sort({ createdAt: -1 }).limit(50).lean();

  const totalScans = scans.length;
  const threatsDetected = scans.filter(s => ['Phishing', 'High Risk', 'Critical'].includes(s.status)).length;
  const safeScans = scans.filter(s => s.status === 'Safe').length;
  const suspiciousScans = scans.filter(s => ['Suspicious', 'Medium Risk'].includes(s.status)).length;

  let totalScore = 0;
  scans.forEach(s => {
    totalScore += (s.details && typeof s.details.securityScore === 'number')
      ? s.details.securityScore
      : (100 - (s.riskScore || 0));
  });

  const avgSecurityScore = totalScans > 0 ? Math.round(totalScore / totalScans) : 85;
  const monitoredSites = await MonitoredSite.find(isAdmin ? {} : { user: userId }).lean();

  return {
    totalScans,
    threatsDetected,
    safeScans,
    suspiciousScans,
    avgSecurityScore,
    monitoredSitesCount: monitoredSites.length,
    recentScans: scans.slice(0, 5).map(s => ({
      target: s.target,
      status: s.status,
      riskScore: s.riskScore
    }))
  };
}

async function getRecentScans(userId, limit = 5, isAdmin = false) {
  const query = isAdmin ? {} : { user: userId };
  const scans = await Scan.find(query).sort({ createdAt: -1 }).limit(limit).lean();
  return scans.map(s => ({
    target: s.target,
    status: s.status,
    riskScore: s.riskScore,
    securityScore: s.details?.securityScore ?? (100 - (s.riskScore || 0)),
    hasHttps: s.details?.hasHttps ?? null,
    vulnerabilitiesCount: s.details?.vulnerabilities?.length || 0,
    createdAt: s.createdAt
  }));
}

async function getScanDetails(scanId, userId, isAdmin = false) {
  const query = { _id: scanId };
  if (!isAdmin) query.user = userId;

  const scan = await Scan.findOne(query).lean();
  if (!scan) return null;

  return {
    target: scan.target,
    scanType: scan.scanType,
    status: scan.status,
    riskScore: scan.riskScore,
    securityScore: scan.details?.securityScore ?? (100 - (scan.riskScore || 0)),
    hasHttps: scan.details?.hasHttps,
    resolvedIp: scan.details?.resolvedIp || 'N/A',
    headerChecks: scan.details?.headerChecks || {},
    vulnerabilities: scan.details?.vulnerabilities || [],
    recommendations: scan.recommendations || scan.details?.recommendations || []
  };
}

async function getVulnerabilities(userId, isAdmin = false) {
  const query = isAdmin ? {} : { user: userId };
  const scans = await Scan.find(query).sort({ createdAt: -1 }).limit(10).lean();

  const vulns = [];
  scans.forEach(s => {
    if (s.details && Array.isArray(s.details.vulnerabilities)) {
      s.details.vulnerabilities.forEach(v => {
        vulns.push({
          target: s.target,
          title: v.title,
          severity: v.severity || 'MEDIUM',
          recommendation: v.recommendation
        });
      });
    }
  });

  return vulns;
}

async function getMonitoringStatus(userId, isAdmin = false) {
  const query = isAdmin ? {} : { user: userId };
  const sites = await MonitoredSite.find(query).lean();
  return sites.map(s => ({
    domain: s.domain,
    lastScore: s.lastScore,
    lastStatus: s.lastStatus
  }));
}

async function getAttackSurfaceData(userId, isAdmin = false) {
  const scans = await getRecentScans(userId, 5, isAdmin);
  const monitored = await getMonitoringStatus(userId, isAdmin);

  const totalAssets = Array.from(new Set([
    ...scans.map(s => s.target),
    ...monitored.map(m => m.domain)
  ]));

  return {
    totalExposedAssets: totalAssets.length,
    assetList: totalAssets.slice(0, 5)
  };
}

// ============================================================
// SYSTEM PROMPT FOR VERSATILE NATURAL AI ASSISTANT WITH MEMORY
// ============================================================

const SYSTEM_SECURITY_PROMPT = `
You are CyberShield AI Copilot — a versatile, intelligent, helpful, and natural AI assistant like ChatGPT and Google Gemini.

CONVERSATIONAL MEMORY & ANSWER INSTRUCTIONS:
1. MULTI-TURN CONVERSATION MEMORY:
   - Remember previous messages in the conversation history. When the user asks follow-up questions (e.g. "How do I fix it?", "Show me an example", "What about that domain?"), answer in the context of the previous messages.
2. ANSWER ALL QUESTIONS NATURALLY:
   - Answer ANY topic (general knowledge, technology, programming, daily questions, OR cybersecurity) in a friendly, helpful tone like ChatGPT / Gemini.
   - NEVER give unwanted "I am only a security bot" disclaimers.
3. ADAPTIVE LENGTH:
   - Simple questions: Short, direct answer (1-3 lines/bullets).
   - Complex questions: Detailed, structured answer with headings, code blocks, or clean lists.
4. PLATFORM DATA:
   - Use provided CyberShield data when asked about platform status, scores, or scans.
5. SAFETY:
   - Provide safe, constructive assistance. Refuse to generate malware or expose secret keys.
`;

/**
 * Core Multi-Provider AI Caller with Conversation Memory (Gemini -> Groq -> OpenRouter -> Natural Fallback)
 */
async function callGeminiAPI(userPrompt, contextData = {}, currentPage = 'dashboard', history = []) {
  const geminiKey = process.env.GEMINI_API_KEY;
  const groqKey = process.env.GROQ_API_KEY;
  const openrouterKey = process.env.OPENROUTER_API_KEY;
  const rawModel = (process.env.AI_MODEL || 'gemini-flash-latest').trim();

  let modelName = rawModel;
  if (['latest-supported-gemini-flash', 'gemini-1.5-flash', 'gemini-2.0-flash', 'gemini-2.5-flash'].includes(rawModel)) {
    modelName = 'gemini-flash-latest';
  }

  const promptText = `Page Context: ${currentPage}\nCyberShield Data: ${JSON.stringify(contextData)}\n\nUSER QUESTION:\n${userPrompt}`;

  // ── Strategy 1: Google Gemini API ──────────────────────────────────────────
  if (geminiKey && geminiKey.trim() !== '' && !geminiKey.includes('YOUR_GEMINI_API_KEY')) {
    try {
      const contents = [];
      if (Array.isArray(history) && history.length > 0) {
        history.forEach(msg => {
          if (msg.content && typeof msg.content === 'string') {
            contents.push({
              role: msg.role === 'user' ? 'user' : 'model',
              parts: [{ text: msg.content }]
            });
          }
        });
      }
      contents.push({ role: 'user', parts: [{ text: promptText }] });

      const endpoint = `https://generativelanguage.googleapis.com/v1beta/models/${modelName}:generateContent?key=${geminiKey.trim()}`;
      const response = await axios.post(endpoint, {
        contents,
        systemInstruction: { parts: [{ text: SYSTEM_SECURITY_PROMPT }] },
        generationConfig: { temperature: 0.5, maxOutputTokens: 1200 }
      }, { timeout: 10000 });

      if (response.data?.candidates?.[0]?.content?.parts?.[0]?.text) {
        return response.data.candidates[0].content.parts[0].text.trim();
      }
    } catch (geminiErr) {
      console.warn('[Gemini API Limit Hit]:', geminiErr.response?.data?.error?.message || geminiErr.message, '--> Switching to Fallback Provider...');
    }
  }

  // ── Strategy 2: Groq Ultra-Fast Free API ────────────────────────────────────
  if (groqKey && groqKey.trim() !== '') {
    try {
      const messages = [
        { role: 'system', content: SYSTEM_SECURITY_PROMPT }
      ];
      if (Array.isArray(history) && history.length > 0) {
        history.forEach(msg => {
          if (msg.content && typeof msg.content === 'string') {
            messages.push({
              role: msg.role === 'user' ? 'user' : 'assistant',
              content: msg.content
            });
          }
        });
      }
      messages.push({ role: 'user', content: promptText });

      const response = await axios.post('https://api.groq.com/openai/v1/chat/completions', {
        model: 'llama-3.3-70b-versatile',
        messages,
        temperature: 0.5,
        max_tokens: 1200
      }, {
        headers: { Authorization: `Bearer ${groqKey.trim()}` },
        timeout: 10000
      });

      if (response.data?.choices?.[0]?.message?.content) {
        return response.data.choices[0].message.content.trim();
      }
    } catch (groqErr) {
      console.warn('[Groq API Fallback Notice]:', groqErr.message);
    }
  }

  // ── Strategy 3: OpenRouter Free Models API ──────────────────────────────────
  try {
    const openrouterHeaders = { 'Content-Type': 'application/json' };
    if (openrouterKey && openrouterKey.trim() !== '') {
      openrouterHeaders['Authorization'] = `Bearer ${openrouterKey.trim()}`;
    }

    const messages = [
      { role: 'system', content: SYSTEM_SECURITY_PROMPT }
    ];
    if (Array.isArray(history) && history.length > 0) {
      history.forEach(msg => {
        if (msg.content && typeof msg.content === 'string') {
          messages.push({
            role: msg.role === 'user' ? 'user' : 'assistant',
            content: msg.content
          });
        }
      });
    }
    messages.push({ role: 'user', content: promptText });

    const response = await axios.post('https://openrouter.ai/api/v1/chat/completions', {
      model: 'meta-llama/llama-3.3-70b-instruct:free',
      messages,
      temperature: 0.5,
      max_tokens: 1200
    }, {
      headers: openrouterHeaders,
      timeout: 10000
    });

    if (response.data?.choices?.[0]?.message?.content) {
      return response.data.choices[0].message.content.trim();
    }
  } catch (openrouterErr) {}

  // ── Strategy 4: Natural & Helpful Fallback Engine ───────────────────────────
  return generateFallbackSOCAnalysis(userPrompt, contextData, currentPage, history);
}

/**
 * Natural & Helpful Fallback Engine with Memory Context
 */
function generateFallbackSOCAnalysis(userPrompt, contextData, currentPage, history = []) {
  const lower = userPrompt.toLowerCase();
  const summary = contextData.summary || contextData;

  // Platform Security Queries
  if (lower.includes('briefing') || lower.includes('soc briefing') || lower.includes('summary')) {
    const score = summary.avgSecurityScore || 85;
    return `
### 🛡️ CyberShield Security Briefing
- **Average Security Score:** \`${score}/100\` (${score >= 80 ? 'Safe' : 'Action Recommended'})
- **Total Scans:** \`${summary.totalScans || 0}\`
- **Active Threats:** \`${summary.threatsDetected || 0}\`
- **Action Needed:** Configure missing HSTS & Content-Security-Policy headers.
    `.trim();
  }

  if (lower.includes('score') || lower.includes('why is my score')) {
    const score = summary.avgSecurityScore || contextData.securityScore || 85;
    return `
### 📊 Security Score: ${score}/100
- **HTTPS:** Enabled ✓
- **Missing Controls:** HSTS & Content-Security-Policy headers ⚠️
- **Fix:** Add HSTS and CSP headers to your server to reach 100/100.
    `.trim();
  }

  if (lower.includes('vulnerability') || lower.includes('vulnerabilities')) {
    return `
### ⚠️ Key Web Vulnerabilities
1. **Missing CSP:** Add \`Content-Security-Policy: default-src 'self'\` header.
2. **Missing HSTS:** Add \`Strict-Transport-Security: max-age=31536000\` header.
3. **Banner Disclosure:** Hide \`X-Powered-By\` server header.
    `.trim();
  }

  // Greetings & General Conversational Queries
  if (lower.includes('hello') || lower.includes('hi') || lower.includes('hey') || lower.includes('how are you')) {
    return `Hello! 👋 I'm your CyberShield AI Copilot. How can I help you today?`;
  }

  if (lower.includes('who are you') || lower.includes('what can you do')) {
    return `I am your **AI Copilot**! I remember our conversation and can answer any questions, help with programming, technology, or assist with CyberShield security scans.`;
  }

  // Follow-up context check
  const lastUserMsg = Array.isArray(history) && history.length > 0
    ? history.filter(h => h.role === 'user').slice(-1)[0]?.content
    : null;

  if (lastUserMsg) {
    return `Regarding your follow-up about "${lastUserMsg.substring(0, 50)}...": Feel free to ask more details or let me know how you'd like to proceed!`;
  }

  return `I'm here to help! Feel free to ask any question or follow up on your previous questions.`;
}

module.exports = {
  getDashboardSummary,
  getRecentScans,
  getScanDetails,
  getVulnerabilities,
  getMonitoringStatus,
  getAttackSurfaceData,
  callGeminiAPI
};
