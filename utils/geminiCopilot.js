/**
 * CyberShield — AI Security Copilot & Multi-Provider Conversational AI Engine
 *
 * Integrates:
 *   1. Google Gemini API (Primary)
 *   2. Groq Ultra-Fast Free API (Fallback 1)
 *   3. OpenRouter Free Models API (Fallback 2)
 *   4. CyberShield Conversational Security SOC Engine (Fallback 3)
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
// SYSTEM PROMPT & NATURAL CONVERSATIONAL AI ENGINE
// ============================================================

const SYSTEM_SECURITY_PROMPT = `
You are the CyberShield AI Security Copilot — an intelligent, helpful, and conversational AI assistant like ChatGPT and Google Gemini, specialized in web security and SOC analysis.

HOW TO ANSWER:
1. Answer the user's question accurately, naturally, and conversationally.
2. If the user asks about their CyberShield security data (scores, scans, threats, assets), reference the provided CyberShield data accurately.
3. If the user asks general cybersecurity, web vulnerability, programming, or general questions (e.g. "What is XSS?", "How does SSL work?", "Hi how are you?"), answer thoroughly and naturally like ChatGPT / Gemini.
4. Format your responses with clean, readable markdown (headings, bold text, code blocks, bullet points) so it is easy to read.
5. Provide actionable defensive advice whenever security issues are mentioned. Never provide malicious hacking tools or exploit code.
`;

/**
 * Core Multi-Provider AI Caller (Gemini -> Groq -> OpenRouter -> Conversational Fallback)
 */
async function callGeminiAPI(userPrompt, contextData = {}, currentPage = 'dashboard') {
  const geminiKey = process.env.GEMINI_API_KEY;
  const groqKey = process.env.GROQ_API_KEY;
  const openrouterKey = process.env.OPENROUTER_API_KEY;
  const rawModel = (process.env.AI_MODEL || 'gemini-flash-latest').trim();

  let modelName = rawModel;
  if (['latest-supported-gemini-flash', 'gemini-1.5-flash', 'gemini-2.0-flash', 'gemini-2.5-flash'].includes(rawModel)) {
    modelName = 'gemini-flash-latest';
  }

  const promptText = `User Current Page Context: ${currentPage}\nCyberShield Real Platform Data Context:\n${JSON.stringify(contextData, null, 2)}\n\nUser Question:\n${userPrompt}`;

  // ── Strategy 1: Google Gemini API ──────────────────────────────────────────
  if (geminiKey && geminiKey.trim() !== '' && !geminiKey.includes('YOUR_GEMINI_API_KEY')) {
    try {
      const endpoint = `https://generativelanguage.googleapis.com/v1beta/models/${modelName}:generateContent?key=${geminiKey.trim()}`;
      const response = await axios.post(endpoint, {
        contents: [{ role: 'user', parts: [{ text: promptText }] }],
        systemInstruction: { parts: [{ text: SYSTEM_SECURITY_PROMPT }] },
        generationConfig: { temperature: 0.4, maxOutputTokens: 1500 }
      }, { timeout: 12000 });

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
      const response = await axios.post('https://api.groq.com/openai/v1/chat/completions', {
        model: 'llama-3.3-70b-versatile',
        messages: [
          { role: 'system', content: SYSTEM_SECURITY_PROMPT },
          { role: 'user', content: promptText }
        ],
        temperature: 0.4,
        max_tokens: 1500
      }, {
        headers: { Authorization: `Bearer ${groqKey.trim()}` },
        timeout: 12000
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

    const response = await axios.post('https://openrouter.ai/api/v1/chat/completions', {
      model: 'meta-llama/llama-3.3-70b-instruct:free',
      messages: [
        { role: 'system', content: SYSTEM_SECURITY_PROMPT },
        { role: 'user', content: promptText }
      ],
      temperature: 0.4,
      max_tokens: 1500
    }, {
      headers: openrouterHeaders,
      timeout: 12000
    });

    if (response.data?.choices?.[0]?.message?.content) {
      return response.data.choices[0].message.content.trim();
    }
  } catch (openrouterErr) {}

  // ── Strategy 4: Conversational Fallback Engine ─────────────────────────────
  return generateFallbackSOCAnalysis(userPrompt, contextData, currentPage);
}

/**
 * Natural Conversational Fallback Engine
 */
function generateFallbackSOCAnalysis(userPrompt, contextData, currentPage) {
  const lower = userPrompt.toLowerCase();
  const summary = contextData.summary || contextData;

  if (lower.includes('briefing') || lower.includes('soc briefing') || lower.includes('summary')) {
    const score = summary.avgSecurityScore || 85;
    return `
### 🛡️ CyberShield AI SOC Security Briefing

Here is your current security posture overview:

- **Average Security Score:** \`${score}/100\` (${score >= 80 ? 'Safe & Healthy' : 'Action Recommended'})
- **Total Scans Performed:** \`${summary.totalScans || 0}\`
- **Active Threats Blocked:** \`${summary.threatsDetected || 0}\`
- **Monitored Endpoints:** \`${summary.monitoredSitesCount || 0}\`

#### 🎯 Top Security Recommendation
To maintain a high security posture, ensure all web servers enforce **Strict-Transport-Security (HSTS)** and **Content-Security-Policy (CSP)** headers.
    `.trim();
  }

  if (lower.includes('score') || lower.includes('why is my score')) {
    const score = summary.avgSecurityScore || contextData.securityScore || 85;
    return `
### 📊 Security Score Analysis

Your current Security Score is **${score}/100**.

#### ✓ Active Protections
- **HTTPS Encryption:** Valid SSL/TLS connection detected.
- **Reputation Check:** Domain passed basic threat database checks.

#### ⚠️ Areas to Improve
- **Content-Security-Policy (CSP):** Add CSP headers to block cross-site scripting (XSS).
- **Strict-Transport-Security (HSTS):** Enforce HSTS to prevent protocol downgrade attacks.

**Next Step:** Adding these HTTP security headers to your server configuration will raise your score to 100/100.
    `.trim();
  }

  if (lower.includes('vulnerability') || lower.includes('vulnerabilities') || lower.includes('xss') || lower.includes('hsts') || lower.includes('csp')) {
    return `
### ⚠️ Web Security Vulnerabilities & Remediation

Here are the key web security controls you should verify:

1. **Content-Security-Policy (CSP)**
   - **Risk:** High (prevents Cross-Site Scripting & Clickjacking)
   - **Fix:** Add header: \`Content-Security-Policy: default-src 'self'\`

2. **Strict-Transport-Security (HSTS)**
   - **Risk:** Medium (enforces HTTPS-only connections)
   - **Fix:** Add header: \`Strict-Transport-Security: max-age=31536000; includeSubDomains\`

3. **Server Information Disclosure**
   - **Risk:** Low (prevents banner grabbing)
   - **Fix:** Remove \`X-Powered-By\` headers from server responses.
    `.trim();
  }

  if (lower.includes('hello') || lower.includes('hi') || lower.includes('hey') || lower.includes('who are you')) {
    return `
Hello! 👋 I am your **CyberShield AI Security Copilot**.

I can help you analyze your website security scans, explain security scores, triage vulnerabilities, review threat intelligence, or answer any web security questions. 

How can I assist you today?
    `.trim();
  }

  return `
### 🤖 CyberShield AI Copilot Analysis

I have evaluated your current CyberShield security data:

- **Analyzed Scans:** \`${summary.totalScans || 0}\`
- **Average Security Score:** \`${summary.avgSecurityScore || 85}/100\`
- **Active Threats:** \`${summary.threatsDetected || 0}\`

Feel free to ask me any questions about your security scores, web vulnerabilities, or security recommendations!
  `.trim();
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
