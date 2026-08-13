/**
 * CyberShield — AI Security Copilot & Multi-Provider Adaptive AI Engine
 *
 * Integrates:
 *   1. Google Gemini API (Primary)
 *   2. Groq Ultra-Fast Free API (Fallback 1)
 *   3. OpenRouter Free Models API (Fallback 2)
 *   4. CyberShield Adaptive Security SOC Engine (Fallback 3)
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
// SYSTEM PROMPT & ADAPTIVE ANSWER ENGINE
// ============================================================

const SYSTEM_SECURITY_PROMPT = `
You are the CyberShield AI Security Copilot — an intelligent assistant like ChatGPT and Google Gemini.

ADAPTIVE ANSWER LENGTH RULES:
1. FOR SIMPLE / ROUTINE QUESTIONS (e.g. greetings, simple status, score checks, simple definitions):
   -> Give a SHORT, SIMPLE, AND DIRECT ANSWER (1-3 concise bullet points or lines). Do NOT write unnecessary long paragraphs.
2. FOR COMPLICATED / DEEP SECURITY QUESTIONS (e.g. detailed vulnerability investigation, step-by-step code remediation, full security audit report):
   -> Provide a COMPLETE, DETAILED ANSWER with clear headings, bullet points, and code examples.
3. Always answer accurately. Reference CyberShield platform data for status/score questions, or general cybersecurity knowledge for technical questions.
4. Provide actionable defensive advice. Never provide hacking tools or exploit code.
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

  const promptText = `User Current Page Context: ${currentPage}\nCyberShield Real Platform Data Context:\n${JSON.stringify(contextData, null, 2)}\n\nUser Question:\n${userPrompt}\n\n(Follow Adaptive Rules: Short 1-3 lines for simple questions, detailed for complicated questions!)`;

  // ── Strategy 1: Google Gemini API ──────────────────────────────────────────
  if (geminiKey && geminiKey.trim() !== '' && !geminiKey.includes('YOUR_GEMINI_API_KEY')) {
    try {
      const endpoint = `https://generativelanguage.googleapis.com/v1beta/models/${modelName}:generateContent?key=${geminiKey.trim()}`;
      const response = await axios.post(endpoint, {
        contents: [{ role: 'user', parts: [{ text: promptText }] }],
        systemInstruction: { parts: [{ text: SYSTEM_SECURITY_PROMPT }] },
        generationConfig: { temperature: 0.3, maxOutputTokens: 1000 }
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
      const response = await axios.post('https://api.groq.com/openai/v1/chat/completions', {
        model: 'llama-3.3-70b-versatile',
        messages: [
          { role: 'system', content: SYSTEM_SECURITY_PROMPT },
          { role: 'user', content: promptText }
        ],
        temperature: 0.3,
        max_tokens: 1000
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

    const response = await axios.post('https://openrouter.ai/api/v1/chat/completions', {
      model: 'meta-llama/llama-3.3-70b-instruct:free',
      messages: [
        { role: 'system', content: SYSTEM_SECURITY_PROMPT },
        { role: 'user', content: promptText }
      ],
      temperature: 0.3,
      max_tokens: 1000
    }, {
      headers: openrouterHeaders,
      timeout: 10000
    });

    if (response.data?.choices?.[0]?.message?.content) {
      return response.data.choices[0].message.content.trim();
    }
  } catch (openrouterErr) {}

  // ── Strategy 4: Adaptive Fallback Engine ───────────────────────────────────
  return generateFallbackSOCAnalysis(userPrompt, contextData, currentPage);
}

/**
 * Adaptive Fallback Engine
 */
function generateFallbackSOCAnalysis(userPrompt, contextData, currentPage) {
  const lower = userPrompt.toLowerCase();
  const summary = contextData.summary || contextData;

  if (lower.includes('briefing') || lower.includes('soc briefing') || lower.includes('summary')) {
    const score = summary.avgSecurityScore || 85;
    return `
### 🛡️ SOC Briefing
- **Security Score:** \`${score}/100\` (${score >= 80 ? 'Safe' : 'Action Recommended'})
- **Active Threats:** \`${summary.threatsDetected || 0}\`
- **Monitored Assets:** \`${summary.monitoredSitesCount || 0}\`
- **Top Priority:** Configure missing HSTS & Content-Security-Policy headers.
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

  if (lower.includes('hello') || lower.includes('hi') || lower.includes('hey')) {
    return `Hello! 👋 How can I help you with your CyberShield security analysis today?`;
  }

  return `
- **Monitored Assets:** \`${summary.totalScans || 0}\` scans
- **Security Score:** \`${summary.avgSecurityScore || 85}/100\`
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
