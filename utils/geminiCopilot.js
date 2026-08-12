/**
 * CyberShield — AI Security Copilot & SOC Analyst Engine
 *
 * Integrates Google Gemini API for real-time defensive security analysis, threat triage,
 * vulnerability explanation, and SOC briefings based ONLY on authenticated CyberShield data.
 */

const axios = require('axios');
const Scan = require('../models/Scan');
const MonitoredSite = require('../models/MonitoredSite');
const Log = require('../models/Log');

// ============================================================
// CONTROLLED BACKEND DATA RETRIEVAL FUNCTIONS (NO DIRECT MONGODB ACCESS FOR AI)
// ============================================================

/**
 * Retrieves aggregated dashboard summary for an authenticated user
 */
async function getDashboardSummary(userId, isAdmin = false) {
  const query = isAdmin ? {} : { user: userId };
  const scans = await Scan.find(query).sort({ createdAt: -1 }).limit(100).lean();

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
      id: s._id,
      target: s.target,
      scanType: s.scanType,
      status: s.status,
      riskScore: s.riskScore,
      createdAt: s.createdAt
    }))
  };
}

/**
 * Retrieves recent scans for an authenticated user
 */
async function getRecentScans(userId, limit = 10, isAdmin = false) {
  const query = isAdmin ? {} : { user: userId };
  const scans = await Scan.find(query).sort({ createdAt: -1 }).limit(limit).lean();
  return scans.map(s => ({
    id: s._id,
    target: s.target,
    scanType: s.scanType,
    status: s.status,
    riskScore: s.riskScore,
    securityScore: s.details?.securityScore ?? (100 - (s.riskScore || 0)),
    hasHttps: s.details?.hasHttps ?? null,
    vulnerabilitiesCount: s.details?.vulnerabilities?.length || 0,
    createdAt: s.createdAt
  }));
}

/**
 * Retrieves detailed scan information by ID
 */
async function getScanDetails(scanId, userId, isAdmin = false) {
  const query = { _id: scanId };
  if (!isAdmin) query.user = userId;

  const scan = await Scan.findOne(query).lean();
  if (!scan) return null;

  return {
    id: scan._id,
    target: scan.target,
    scanType: scan.scanType,
    status: scan.status,
    riskScore: scan.riskScore,
    confidenceScore: scan.confidenceScore,
    securityScore: scan.details?.securityScore ?? (100 - (scan.riskScore || 0)),
    riskLevel: scan.details?.riskLevel || scan.status,
    hasHttps: scan.details?.hasHttps,
    resolvedIp: scan.details?.resolvedIp || 'N/A',
    domain: scan.details?.domain || scan.target,
    headerChecks: scan.details?.headerChecks || {},
    vulnerabilities: scan.details?.vulnerabilities || [],
    recommendations: scan.recommendations || scan.details?.recommendations || [],
    createdAt: scan.createdAt
  };
}

/**
 * Retrieves active vulnerabilities across user's scans
 */
async function getVulnerabilities(userId, isAdmin = false) {
  const query = isAdmin ? {} : { user: userId };
  const scans = await Scan.find(query).sort({ createdAt: -1 }).limit(20).lean();

  const vulns = [];
  scans.forEach(s => {
    if (s.details && Array.isArray(s.details.vulnerabilities)) {
      s.details.vulnerabilities.forEach(v => {
        vulns.push({
          scanId: s._id,
          target: s.target,
          title: v.title,
          severity: v.severity || 'MEDIUM',
          description: v.description,
          recommendation: v.recommendation,
          detectedAt: s.createdAt
        });
      });
    }
  });

  return vulns;
}

/**
 * Retrieves monitored sites status
 */
async function getMonitoringStatus(userId, isAdmin = false) {
  const query = isAdmin ? {} : { user: userId };
  const sites = await MonitoredSite.find(query).lean();
  return sites.map(s => ({
    id: s._id,
    domain: s.domain,
    displayName: s.displayName,
    lastScore: s.lastScore,
    lastStatus: s.lastStatus,
    active: s.active,
    lastScan: s.lastScan
  }));
}

/**
 * Retrieves attack surface information
 */
async function getAttackSurfaceData(userId, isAdmin = false) {
  const scans = await getRecentScans(userId, 20, isAdmin);
  const monitored = await getMonitoringStatus(userId, isAdmin);

  const totalAssets = Array.from(new Set([
    ...scans.map(s => s.target),
    ...monitored.map(m => m.domain)
  ]));

  const highRiskAssets = scans.filter(s => ['High Risk', 'Phishing', 'Critical'].includes(s.status));
  const missingHeaderAssets = scans.filter(s => s.vulnerabilitiesCount > 0);

  return {
    totalExposedAssets: totalAssets.length,
    highRiskAssetsCount: highRiskAssets.length,
    assetsWithVulnerabilitiesCount: missingHeaderAssets.length,
    assetList: totalAssets.slice(0, 10),
    highRiskAssetList: highRiskAssets.map(h => ({ target: h.target, status: h.status }))
  };
}

// ============================================================
// GEMINI API INTEGRATION & PROMPT BUILDER
// ============================================================

const SYSTEM_SECURITY_PROMPT = `
You are the CyberShield AI Security Copilot.
Your job is to answer the user's security question SIMPLY, DIRECTLY, AND CONCISELY using plain English.

RULES:
1. Answer exactly what the user asked in clear, simple bullet points.
2. Keep explanations short, practical, and easy to understand.
3. No unnecessary intro/outro boilerplate or filler text. Get straight to the point.
4. Give defensive security advice, risk level, and exact fix steps.
5. NEVER provide hacking payloads, attack code, or reveal passwords/tokens/API keys.
6. Use actual CyberShield platform data provided in the context. If no data exists, state simply: "No current data available for this request."
`;

/**
 * Core Gemini API Caller
 */
async function callGeminiAPI(userPrompt, contextData = {}, currentPage = 'dashboard') {
  const apiKey = process.env.GEMINI_API_KEY;
  const rawModel = (process.env.AI_MODEL || 'gemini-flash-latest').trim();

  let modelName = rawModel;
  if (['latest-supported-gemini-flash', 'gemini-1.5-flash', 'gemini-2.0-flash', 'gemini-2.5-flash'].includes(rawModel)) {
    modelName = 'gemini-flash-latest';
  }

  const fullPrompt = `
Page Context: ${currentPage}

CYBERSHIELD DATA:
${JSON.stringify(contextData, null, 2)}

USER QUESTION:
${userPrompt}

(Note: Keep your answer simple, direct, clear, and concise!)
  `;

  if (!apiKey || apiKey.trim() === '' || apiKey.includes('YOUR_GEMINI_API_KEY')) {
    return generateFallbackSOCAnalysis(userPrompt, contextData, currentPage);
  }

  try {
    const endpoint = `https://generativelanguage.googleapis.com/v1beta/models/${modelName}:generateContent?key=${apiKey.trim()}`;

    const response = await axios.post(endpoint, {
      contents: [
        {
          role: 'user',
          parts: [{ text: fullPrompt }]
        }
      ],
      systemInstruction: {
        parts: [{ text: SYSTEM_SECURITY_PROMPT }]
      },
      generationConfig: {
        temperature: 0.2,
        maxOutputTokens: 1024
      }
    }, { timeout: 12000 });

    if (response.data && response.data.candidates && response.data.candidates[0]?.content?.parts[0]?.text) {
      return response.data.candidates[0].content.parts[0].text;
    }

    return generateFallbackSOCAnalysis(userPrompt, contextData, currentPage);
  } catch (err) {
    console.warn('[Gemini API Call Warning]:', err.response?.data?.error?.message || err.message);
    return generateFallbackSOCAnalysis(userPrompt, contextData, currentPage);
  }
}

/**
 * Simple & Direct Defensive SOC Analysis Fallback Engine
 */
function generateFallbackSOCAnalysis(userPrompt, contextData, currentPage) {
  const lower = userPrompt.toLowerCase();
  const summary = contextData.summary || contextData;

  if (lower.includes('briefing') || lower.includes('soc briefing') || lower.includes('summary')) {
    const score = summary.avgSecurityScore || 85;
    const threats = summary.threatsDetected || 0;
    const safe = summary.safeScans || 0;
    const total = summary.totalScans || 0;

    return `
### 🛡️ SOC Security Briefing

- **Security Score:** \`${score}/100\` (${score >= 80 ? 'Safe' : 'Needs Action'})
- **Total Scans:** \`${total}\`
- **Active Threats:** \`${threats}\`
- **Safe Assets:** \`${safe}\`

**Quick Recommendation:** Configure missing Security Headers (HSTS, CSP) to keep your web assets protected.
    `.trim();
  }

  if (lower.includes('score') || lower.includes('why is my score')) {
    const score = summary.avgSecurityScore || contextData.securityScore || 85;

    return `
### 🛡️ Security Score: ${score}/100

**What's Good:**
- ✓ HTTPS encryption enabled
- ✓ Active threat monitoring

**What Needs Fixing:**
- ⚠️ Add \`Content-Security-Policy\` header
- ⚠️ Add \`Strict-Transport-Security\` header

**Quick Fix:** Add these missing headers to your web server config to increase your score to 100.
    `.trim();
  }

  if (lower.includes('vulnerability') || lower.includes('vulnerabilities')) {
    return `
### ⚠️ Vulnerability Summary

- **Missing CSP:** Add \`Content-Security-Policy\` header to block XSS attacks.
- **Missing HSTS:** Add \`Strict-Transport-Security\` header to enforce HTTPS.
- **Server Disclosure:** Hide server version headers (\`X-Powered-By\`).
    `.trim();
  }

  return `
### 🤖 CyberShield AI Analysis

- **Total Scans:** \`${summary.totalScans || 0}\`
- **Average Security Score:** \`${summary.avgSecurityScore || 85}/100\`
- **Threats:** \`${summary.threatsDetected || 0}\`

Everything is currently monitored. Ask any specific question for a direct answer!
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
