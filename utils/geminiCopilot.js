/**
 * CyberShield — AI Security Copilot & Multi-Provider AI Engine
 *
 * Integrates:
 *   1. Google Gemini API (Primary)
 *   2. Groq Ultra-Fast Free API (Fallback 1)
 *   3. OpenRouter Free Models API (Fallback 2)
 *   4. Deterministic CyberShield SOC Engine (Fallback 3)
 */

const axios = require('axios');
const Scan = require('../models/Scan');
const MonitoredSite = require('../models/MonitoredSite');
const Log = require('../models/Log');

// ============================================================
// CONTROLLED BACKEND DATA RETRIEVAL FUNCTIONS (NO DIRECT MONGODB ACCESS FOR AI)
// ============================================================

async function getDashboardSummary(userId, isAdmin = false) {
  const query = isAdmin ? {} : { user: userId };
  const scans = await Scan.find(query).sort({ createdAt: -1 }).limit(30).lean();

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
    monitoredSitesCount: monitoredSites.length
  };
}

async function getRecentScans(userId, limit = 5, isAdmin = false) {
  const query = isAdmin ? {} : { user: userId };
  const scans = await Scan.find(query).sort({ createdAt: -1 }).limit(limit).lean();
  return scans.map(s => ({
    target: s.target,
    status: s.status,
    riskScore: s.riskScore,
    securityScore: s.details?.securityScore ?? (100 - (s.riskScore || 0))
  }));
}

async function getScanDetails(scanId, userId, isAdmin = false) {
  const query = { _id: scanId };
  if (!isAdmin) query.user = userId;

  const scan = await Scan.findOne(query).lean();
  if (!scan) return null;

  return {
    target: scan.target,
    status: scan.status,
    riskScore: scan.riskScore,
    securityScore: scan.details?.securityScore ?? (100 - (scan.riskScore || 0)),
    hasHttps: scan.details?.hasHttps,
    vulnerabilities: scan.details?.vulnerabilities || []
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
          severity: v.severity || 'MEDIUM'
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
// SYSTEM PROMPT & MULTI-PROVIDER AI CASCADE
// ============================================================

const SYSTEM_SECURITY_PROMPT = `
You are CyberShield AI Security Copilot.

STRICT SHORT ANSWER RULES:
1. Provide SHORT, SIMPLE, AND DIRECT ANSWERS (maximum 3-5 bullet points / brief lines).
2. Answer ONLY the exact question asked. No intro, no summary headers, no long explanations.
3. Use plain English and clean bullet points.
4. Give risk level and immediate defensive fix steps if applicable.
5. NEVER provide hacking payloads, attack code, or reveal passwords/tokens/keys.
`;

/**
 * Core Multi-Provider AI Caller (Gemini -> Groq -> OpenRouter -> Deterministic Engine)
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

  const promptText = `Page: ${currentPage}\nDATA: ${JSON.stringify(contextData)}\n\nUSER QUESTION: ${userPrompt}\n\n(IMPORTANT: Answer in 2-4 short, simple bullet points ONLY!)`;

  // ── Strategy 1: Google Gemini API ──────────────────────────────────────────
  if (geminiKey && geminiKey.trim() !== '' && !geminiKey.includes('YOUR_GEMINI_API_KEY')) {
    try {
      const endpoint = `https://generativelanguage.googleapis.com/v1beta/models/${modelName}:generateContent?key=${geminiKey.trim()}`;
      const response = await axios.post(endpoint, {
        contents: [{ role: 'user', parts: [{ text: promptText }] }],
        systemInstruction: { parts: [{ text: SYSTEM_SECURITY_PROMPT }] },
        generationConfig: { temperature: 0.2, maxOutputTokens: 250 }
      }, { timeout: 7000 });

      if (response.data?.candidates?.[0]?.content?.parts?.[0]?.text) {
        return response.data.candidates[0].content.parts[0].text.trim();
      }
    } catch (geminiErr) {
      console.warn('[Gemini API Limit Hit]:', geminiErr.response?.data?.error?.message || geminiErr.message);
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
        temperature: 0.2,
        max_tokens: 250
      }, {
        headers: { Authorization: `Bearer ${groqKey.trim()}` },
        timeout: 7000
      });

      if (response.data?.choices?.[0]?.message?.content) {
        return response.data.choices[0].message.content.trim();
      }
    } catch (groqErr) {}
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
      temperature: 0.2,
      max_tokens: 250
    }, {
      headers: openrouterHeaders,
      timeout: 7000
    });

    if (response.data?.choices?.[0]?.message?.content) {
      return response.data.choices[0].message.content.trim();
    }
  } catch (openrouterErr) {}

  // ── Strategy 4: CyberShield Short Deterministic SOC Engine ────────────────
  return generateFallbackSOCAnalysis(userPrompt, contextData, currentPage);
}

/**
 * Short, Simple, & Direct Fallback Engine
 */
function generateFallbackSOCAnalysis(userPrompt, contextData, currentPage) {
  const lower = userPrompt.toLowerCase();
  const summary = contextData.summary || contextData;

  if (lower.includes('briefing') || lower.includes('soc briefing') || lower.includes('summary')) {
    const score = summary.avgSecurityScore || 85;
    return `
- **Security Score:** ${score}/100
- **Total Scans:** ${summary.totalScans || 0}
- **Active Threats:** ${summary.threatsDetected || 0}
- **Action Needed:** Add missing HSTS & CSP security headers.
    `.trim();
  }

  if (lower.includes('score') || lower.includes('why is my score')) {
    const score = summary.avgSecurityScore || contextData.securityScore || 85;
    return `
- **Current Score:** ${score}/100
- **Status:** ${score >= 80 ? 'Safe' : 'Medium Risk'}
- **Fix Needed:** Enable \`Strict-Transport-Security\` and \`Content-Security-Policy\` headers.
    `.trim();
  }

  if (lower.includes('vulnerability') || lower.includes('vulnerabilities')) {
    return `
- **Missing CSP:** Add \`Content-Security-Policy: default-src 'self'\` to prevent XSS.
- **Missing HSTS:** Add \`Strict-Transport-Security: max-age=31536000\` to enforce HTTPS.
- **Header Disclosure:** Remove \`X-Powered-By\` headers.
    `.trim();
  }

  return `
- **Monitored Assets:** ${summary.totalScans || 0} scans
- **Security Score:** ${summary.avgSecurityScore || 85}/100
- **Status:** Active & Monitored
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
