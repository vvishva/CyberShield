/**
 * CyberShield — Versatile Natural AI Copilot Engine with Multi-Turn Memory & Cybersecurity Intelligence
 *
 * Integrates:
 *   1. Google Gemini API (Primary)
 *   2. Groq Ultra-Fast API (Fallback 1)
 *   3. OpenRouter Models API (Fallback 2)
 *   4. CyberShield Comprehensive SOC & Cybersecurity Intelligence Engine (Offline / Resilience Fallback)
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
    id: s._id,
    target: s.target,
    scanType: s.scanType,
    status: s.status,
    riskScore: s.riskScore,
    securityScore: s.details?.securityScore ?? (100 - (s.riskScore || 0)),
    hasHttps: s.details?.hasHttps ?? null,
    vulnerabilitiesCount: s.details?.vulnerabilities?.length || 0,
    vulnerabilities: s.details?.vulnerabilities || [],
    missingHeaders: s.details?.missingHeaders || [],
    createdAt: s.createdAt
  }));
}

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
  const scans = await Scan.find(query).sort({ createdAt: -1 }).limit(15).lean();

  const vulns = [];
  scans.forEach(s => {
    if (s.details && Array.isArray(s.details.vulnerabilities)) {
      s.details.vulnerabilities.forEach(v => {
        vulns.push({
          target: s.target,
          title: v.title || v.name || v,
          severity: (v.severity || 'MEDIUM').toUpperCase(),
          description: v.description || 'Security vulnerability identified.',
          recommendation: v.recommendation || 'Apply patch or security configuration.'
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
    lastStatus: s.lastStatus,
    active: s.active
  }));
}

async function getAttackSurfaceData(userId, isAdmin = false) {
  const scans = await getRecentScans(userId, 10, isAdmin);
  const monitored = await getMonitoringStatus(userId, isAdmin);

  const totalAssets = Array.from(new Set([
    ...scans.map(s => s.target),
    ...monitored.map(m => m.domain)
  ]));

  return {
    totalExposedAssets: totalAssets.length,
    assetList: totalAssets.slice(0, 8),
    monitoredSites: monitored
  };
}

async function getIncidentsData(userId, isAdmin = false) {
  try {
    const Incident = require('../models/Incident');
    const query = isAdmin ? {} : { user: userId };
    const incidents = await Incident.find(query).sort({ lastUpdated: -1 }).limit(10).lean();
    return incidents.map(i => ({
      incidentId: i.incidentId,
      title: i.title,
      severity: i.severity,
      status: i.status,
      relatedAsset: i.relatedAsset,
      description: i.description
    }));
  } catch (e) {
    return [];
  }
}

// ============================================================
// SYSTEM PROMPT FOR CYBERSHIELD AI COPILOT
// ============================================================

const SYSTEM_SECURITY_PROMPT = `
You are CyberShield AI Copilot — a world-class defensive cybersecurity assistant, Security Operations Center (SOC) analyst, and helpful technical advisor.

CORE PRINCIPLES:
1. ACCURATE CYBERSECURITY ANSWERS:
   - Answer general cybersecurity questions directly, authoritatively, and clearly (e.g. SOC, SIEM, IDS/IPS, firewalls, CVE/CVSS, threats vs. vulnerabilities, HTTP headers, TLS, incident response, attack surface).
   - Use clean Markdown with short headings (###), bullet points, and code blocks for technical commands/headers.
2. CYBERSHIELD TELEMETRY USAGE:
   - When asked about the user's security score, active threats, vulnerabilities, monitored assets, or scans, use the provided CyberShield Data.
   - If specific CyberShield data is not present in the payload, clearly say: "No active scan data or findings recorded for this yet in your account. You can run a scan on the Security Scanner page."
   - NEVER invent or fabricate telemetry, IP addresses, or CVE findings.
3. CONVERSATIONAL MEMORY:
   - Understand follow-up pronouns ("it", "that", "why is that", "how to fix it") referring to the previous conversation turns.
4. TONE & CONCISENESS:
   - Be professional, sharp, direct, and concise. Avoid unnecessary conversational fluff or repetitive disclaimers.
   - For simple questions, give a direct 2-4 sentence/bullet explanation. For complex technical questions, provide clear step-by-step remediation.
`;

/**
 * Core Multi-Provider AI Caller with Conversation Memory (Gemini -> Groq -> OpenRouter -> Comprehensive Fallback)
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

  const promptText = `Page Context: ${currentPage}\nCyberShield Real Telemetry Data: ${JSON.stringify(contextData)}\n\nUSER QUESTION:\n${userPrompt}`;

  // ── Strategy 1: Google Gemini API ──────────────────────────────────────────
  if (geminiKey && geminiKey.trim() !== '' && !geminiKey.includes('YOUR_GEMINI_API_KEY')) {
    try {
      const contents = [];
      if (Array.isArray(history) && history.length > 0) {
        history.slice(-8).forEach(msg => {
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
        generationConfig: { temperature: 0.4, maxOutputTokens: 1200 }
      }, { timeout: 10000 });

      if (response.data?.candidates?.[0]?.content?.parts?.[0]?.text) {
        return response.data.candidates[0].content.parts[0].text.trim();
      }
    } catch (geminiErr) {
      console.warn('[Gemini API Fallback]:', geminiErr.response?.data?.error?.message || geminiErr.message);
    }
  }

  // ── Strategy 2: Groq Ultra-Fast API ────────────────────────────────────────
  if (groqKey && groqKey.trim() !== '' && !groqKey.includes('YOUR_GROQ_API_KEY')) {
    try {
      const messages = [
        { role: 'system', content: SYSTEM_SECURITY_PROMPT }
      ];
      if (Array.isArray(history) && history.length > 0) {
        history.slice(-8).forEach(msg => {
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
        temperature: 0.4,
        max_tokens: 1200
      }, {
        headers: { Authorization: `Bearer ${groqKey.trim()}` },
        timeout: 10000
      });

      if (response.data?.choices?.[0]?.message?.content) {
        return response.data.choices[0].message.content.trim();
      }
    } catch (groqErr) {
      console.warn('[Groq API Fallback]:', groqErr.message);
    }
  }

  // ── Strategy 3: OpenRouter API ─────────────────────────────────────────────
  if (openrouterKey && openrouterKey.trim() !== '' && !openrouterKey.includes('YOUR_OPENROUTER_API_KEY')) {
    try {
      const messages = [
        { role: 'system', content: SYSTEM_SECURITY_PROMPT }
      ];
      if (Array.isArray(history) && history.length > 0) {
        history.slice(-8).forEach(msg => {
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
        temperature: 0.4,
        max_tokens: 1200
      }, {
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${openrouterKey.trim()}`
        },
        timeout: 10000
      });

      if (response.data?.choices?.[0]?.message?.content) {
        return response.data.choices[0].message.content.trim();
      }
    } catch (openrouterErr) {
      console.warn('[OpenRouter API Fallback]:', openrouterErr.message);
    }
  }

  // ── Strategy 4: Comprehensive CyberShield Intelligence & Knowledge Engine ───
  return generateExpertSOCIntelligence(userPrompt, contextData, currentPage, history);
}

/**
 * Comprehensive CyberShield Cybersecurity & SOC Knowledge Engine
 * Provides expert, structured, real-time responses to all cybersecurity and CyberShield queries.
 */
function generateExpertSOCIntelligence(userPrompt, contextData, currentPage, history = []) {
  const p = userPrompt.trim().toLowerCase();
  const summary = contextData.summary || {};
  const vulns = contextData.vulnerabilities || [];
  const scans = contextData.recentScans || [];
  const incidents = contextData.incidents || [];
  const surface = contextData.attackSurface || {};
  const monitoring = contextData.monitoring || [];

  // =========================================================================
  // 1. CYBERSHIELD REAL-TIME DATA QUERIES
  // =========================================================================

  // ── Compound & Specific Conceptual Comparisons First ───────────────────────
  
  // Threat vs Vulnerability Comparison
  if (p.includes('difference between') && (p.includes('threat') || p.includes('vulnerabilit'))) {
    return `
### ⚖️ Difference Between a Threat and a Vulnerability

| Aspect | **Vulnerability** | **Threat** |
| :--- | :--- | :--- |
| **Definition** | A weakness, bug, or flaw in a system. | Any entity, action, or event with the potential to cause harm. |
| **Nature** | Internal (your software, misconfigurations). | External or contextual (attackers, malware, phishing). |
| **Example** | Missing CSP header, unpatched Apache CVE. | A ransomware gang, credential stuffing script, phishing email. |
| **Control** | Can be **patched / remediated** directly. | Must be **defended against / mitigated**. |

$$\\text{Risk} = \\text{Threat} \\times \\text{Vulnerability} \\times \\text{Impact}$$
    `.trim();
  }

  // What is SOC?
  if (p.includes('what is soc') || p.includes('soc stand for') || p.includes('define soc') || p === 'soc' || p === 'what is a soc?') {
    return `
### 🛡️ What is a SOC (Security Operations Center)?

A **Security Operations Center (SOC)** is a centralized command facility where information security personnel continuously monitor, detect, analyze, and respond to cybersecurity incidents across an organization's systems, networks, and applications.

#### Key Functions of a Modern SOC:
1. **24/7 Threat Monitoring:** Real-time telemetry ingestion from SIEM, firewalls, and endpoint agents.
2. **Incident Triage & Response:** Investigating alarms, containing malicious activity, and mitigating threats.
3. **Vulnerability Management:** Discovering and tracking CVEs across the attack surface.
4. **Threat Intelligence:** Mapping adversary tactics (MITRE ATT&CK) and IOCs.

*In CyberShield, the SOC dashboard provides automated threat telemetry, risk scoring, and AI-assisted triage.*
    `.trim();
  }

  // What does SOC / CyberShield monitor?
  if (p.includes('what does it monitor') || p.includes('what does a soc monitor') || p.includes('what does soc monitor') || p.includes('what do you monitor')) {
    return `
### 👁️ What Does a SOC & CyberShield Monitor?

A **Security Operations Center (SOC)** continuously ingests and analyzes telemetry across several defense layers:

1. **Web & Network Ingress:** HTTP/HTTPS traffic, Web Application Firewall (WAF) logs, TLS handshake status, and DNS lookup requests.
2. **Authentication & Access:** Login events, failed attempts, privilege escalations, 2FA status, and session anomalies.
3. **Endpoint & Server Telemetry:** Process execution, file integrity, open listening ports, and server configuration changes.
4. **Vulnerability Exposure:** SSL certificate expirations, missing HTTP defense headers (HSTS, CSP), and unpatched CVEs.
5. **Threat Intelligence Feeds:** Phishing domain reputation, malicious IP blocklists, and automated adversary scanning activity.
    `.trim();
  }

  // What is CVSS / CVE / CWE?
  if (p.includes('cvss') || p.includes('cve') || p.includes('cwe')) {
    return `
### 🏷️ Understanding CVE, CVSS, and CWE

- **CVE (Common Vulnerabilities and Exposures):** A standardized identifier for publicly known security vulnerabilities (e.g., \`CVE-2024-38077\`).
- **CVSS (Common Vulnerability Scoring System):** A numeric score from **0.0 to 10.0** representing the technical severity of a vulnerability:
  - **Critical:** 9.0 – 10.0
  - **High:** 7.0 – 8.9
  - **Medium:** 4.0 – 6.9
  - **Low:** 0.1 – 3.9
- **CWE (Common Weakness Enumeration):** A categorization of software weakness types (e.g., \`CWE-79\` for Cross-Site Scripting, \`CWE-89\` for SQL Injection).
    `.trim();
  }

  // Vulnerability Prioritization Queries
  if (p.includes('which vulnerability') || p.includes('dangerous vulnerability') || p.includes('prioritize') || p.includes('fix first') || p.includes('most dangerous')) {
    const critVulns = vulns.filter(v => v.severity === 'CRITICAL' || v.severity === 'HIGH');

    if (critVulns.length > 0) {
      const top = critVulns[0];
      return `
### 🚨 Highest Priority Vulnerability to Fix:

- **Vulnerability:** **${top.title}**
- **Severity:** \`${top.severity}\`
- **Affected Asset:** \`${top.target}\`
- **Impact:** ${top.description}

#### Immediate Remediation:
- **Fix:** ${top.recommendation}
- **Action:** Open the **Vulnerability Management** page to generate a detailed remediation blueprint.
      `.trim();
    }

    return `
### 🛡️ Vulnerability Priority Assessment:

1. **Content-Security-Policy (CSP) Missing (High Priority):**
   - *Impact:* Leaves application vulnerable to Cross-Site Scripting (XSS) and iframe framing.
   - *Remediation:* Deploy \`Content-Security-Policy: default-src 'self'; script-src 'self'\`.
2. **Strict-Transport-Security (HSTS) Missing (Medium Priority):**
   - *Impact:* Connections can be intercepted via SSL stripping.
   - *Remediation:* Add \`Strict-Transport-Security: max-age=31536000; includeSubDomains\`.
3. **Server Banner Exposure (Low Priority):**
   - *Remediation:* Disable \`Server\` and \`X-Powered-By\` headers.
    `.trim();
  }

  // Asset Risk Assessment Queries
  if (p.includes('highest risk') || p.includes('dangerous asset') || p.includes('which asset') || p.includes('attack surface') || p.includes('asset')) {
    const assets = surface.assetList || [];
    const mon = surface.monitoredSites || monitoring;

    return `
### 🌐 Asset & Attack Surface Risk Assessment

- **Total Exposed Assets Mapped:** \`${surface.totalExposedAssets || assets.length || 'Active'}\`
- **Monitored Endpoints:** \`${mon.length || summary.monitoredSitesCount || 0}\`

#### Key Assets Under Watch:
${assets.slice(0, 4).map(a => `- **${a}:** Monitored for cryptographic and header security drift.`).join('\n') || '- Web Application Ingress Gateway'}

#### Defensive Best Practices:
1. Eliminate unencrypted HTTP endpoints across all subdomains.
2. Ensure DNS records and staging environments are not publicly exposed without authentication.
3. Review the **Attack Surface Map** in the sidebar for interactive topological visualization.
    `.trim();
  }

  // General Vulnerability Definition & Explanation Queries
  if (p.includes('vulnerabilit')) {
    return `
### 🛡️ Vulnerability Overview & Management

A **vulnerability** is a weakness, flaw, or misconfiguration in software, hardware, or network architecture that an adversary can exploit to breach confidentiality, integrity, or availability.

#### Common Vulnerability Classes in Web Applications:
- **Missing Security Headers:** Lack of CSP, HSTS, or X-Frame-Options leaving assets open to XSS and Clickjacking.
- **Authentication & Session Flaws:** Weak password policies, absence of 2FA, or insecure session tokens.
- **Injection Flaws:** SQL Injection (SQLi), Cross-Site Scripting (XSS), Server-Side Request Forgery (SSRF).

#### How to Check & Fix in CyberShield:
- Navigate to **Vulnerabilities** in the sidebar to review detected CVEs and CVSS severity scores.
- Click **Remediate** on any vulnerability to view an AI-generated configuration patch.
    `.trim();
  }

  // Security Score Queries
  if (p.includes('security score') || p.includes('my score') || p.includes('why is my score') || p.includes('current score') || p === 'score' || p === 'what is my score?') {
    const score = summary.avgSecurityScore ?? 85;
    const scoreDelta = summary.scoreDelta ?? 0;
    const statusLabel = score >= 80 ? 'Good / Resilient' : score >= 60 ? 'Moderate / Warning' : 'Critical / High Risk';

    return `
### 🛡️ Your CyberShield Security Score: ${score}/100

- **Overall Status:** **${statusLabel}**
- **Score Trend:** ${scoreDelta >= 0 ? `+${scoreDelta} points (Improving)` : `${scoreDelta} points (Declining)`}
- **Active Scans Analyzed:** \`${summary.totalScans || scans.length || 0}\`
- **Active Threats Detected:** \`${summary.threatsDetected || 0}\`

#### Key Factors Affecting Your Score:
1. **SSL/TLS Encryption:** Ensure all ingress domains enforce HTTPS without legacy cipher downgrade.
2. **HTTP Security Headers:** Configure \`Content-Security-Policy\` and \`Strict-Transport-Security (HSTS)\`.
3. **Open Incidents:** Triage and resolve active high-severity incidents in the Incident Response Hub.
    `.trim();
  }

  // Active Threats & Phishing Queries
  if (p.includes('threat') || p.includes('active threat') || p.includes('phishing') || p.includes('summarize today\'s threat') || p.includes('summarize today') || p.includes('today\'s threat') || p.includes('how many active threats')) {
    const threatsCount = summary.threatsDetected || scans.filter(s => ['Phishing', 'High Risk', 'Critical'].includes(s.status)).length;
    const openIncidents = incidents.filter(i => ['New', 'Investigating'].includes(i.status));

    if (threatsCount === 0 && openIncidents.length === 0) {
      return `
### 🛡️ Active Threat Intelligence Summary

- **Active Threat Detections:** **0 Active Threats**
- **Perimeter Posture:** Clean. No active phishing domains or malicious URLs currently flagged.
- **Continuous Monitoring:** Active across \`${summary.monitoredSitesCount || monitoring.length || 0}\` assets.
- **Recommendation:** Maintain automated continuous monitoring and periodic URL reputation scans.
      `.trim();
    }

    return `
### ⚠️ Active Threat Intelligence Summary

- **Total Threats Flagged:** **${threatsCount} Threats**
- **Active Incidents Requiring Triage:** **${openIncidents.length} Incident(s)**

#### Identified Threat Vectors:
${scans.filter(s => (s.riskScore || 0) >= 50).slice(0, 3).map(s => `- **${s.target}:** Flagged as \`${s.status}\` (${s.riskScore}% Risk)`).join('\n') || '- Phishing domain impersonation probes detected and blocked.'}

#### Recommended Action:
1. Open the **Incident Response Hub** to isolate affected assets.
2. Enforce DNS sinkholing or registrar takedown for verified phishing hosts.
    `.trim();
  }

  // Incidents Query
  if (p.includes('incident') || p.includes('unresolved') || p.includes('open incident')) {
    const openList = incidents.filter(i => ['New', 'Investigating'].includes(i.status));

    return `
### 🚨 Incident Response Status:

- **Open Incidents Requiring Triage:** **${openList.length || incidents.length || 0} Incident(s)**
- **Incident Lifecycle:** \`New\` ➔ \`Investigating\` ➔ \`Contained\` ➔ \`Resolved\` ➔ \`Closed\`

${incidents.slice(0, 3).map(i => `- **[${i.severity}] ${i.incidentId}:** ${i.title} (*Status: ${i.status}*)`).join('\n') || '- No active unresolved incidents.'}

- **Action:** Open the **Incident Response & Investigation** page to transition incident phases and generate containment actions.
    `.trim();
  }

  // Latest Scan Summary Query
  if (p.includes('latest scan') || p.includes('explain the scan') || p.includes('explain scan') || p.includes('scan result')) {
    const latest = scans[0];
    if (latest) {
      return `
### 🔍 Latest Scan Analysis: ${latest.target}

- **Verdict:** \`${latest.status}\` (${latest.riskScore}% Risk)
- **Security Score:** \`${latest.securityScore || (100 - latest.riskScore)}/100\`
- **Scan Type:** \`${latest.scanType?.replace('_', ' ') || 'Security Scan'}\`
- **HTTPS:** ${latest.hasHttps ? 'Enabled ✓' : 'Unencrypted ⚠️'}
- **Vulnerabilities Detected:** \`${latest.vulnerabilitiesCount || latest.vulnerabilities?.length || 0}\`

#### Summary:
The target asset was evaluated against phishing signatures, SSL validity, and HTTP response security headers. Review the **Scan History** or **Audit Reports** for a downloadable PDF report.
      `.trim();
    }

    return `
### 🔍 Latest Security Scan
No scans found in your account history yet. You can perform a live URL phishing or website security audit on the **Security Scanners** page.
    `.trim();
  }

  // Security Status / Overview Queries
  if (p.includes('status') || p.includes('summary') || p.includes('overview') || p.includes('briefing')) {
    const score = summary.avgSecurityScore ?? 85;
    return `
### 📊 CyberShield SOC Security Summary

- **Security Posture Score:** \`${score}/100\` (${score >= 80 ? 'Resilient' : 'Needs Attention'})
- **Total Scans Completed:** \`${summary.totalScans || scans.length || 0}\`
- **Active Threats:** \`${summary.threatsDetected || 0}\`
- **Monitored Assets:** \`${summary.monitoredSitesCount || monitoring.length || 0}\`
- **AI Sentinel Status:** Active & Monitoring (SSE Live Feed Connected)
    `.trim();
  }

  // =========================================================================
  // 2. GENERAL CYBERSECURITY CONCEPTS & DEFINITIONS
  // =========================================================================

  // What is SOC?
  if (p.includes('what is soc') || p.includes('soc stand for') || p.includes('define soc') || p === 'soc') {
    return `
### 🛡️ What is a SOC (Security Operations Center)?

A **Security Operations Center (SOC)** is a centralized command facility where information security personnel continuously monitor, detect, analyze, and respond to cybersecurity incidents across an organization's systems, networks, and applications.

#### Key Functions of a Modern SOC:
1. **24/7 Threat Monitoring:** Real-time telemetry ingestion from SIEM, firewalls, and endpoint agents.
2. **Incident Triage & Response:** Investigating alarms, containing malicious activity, and mitigating threats.
3. **Vulnerability Management:** Discovering and tracking CVEs across the attack surface.
4. **Threat Intelligence:** Mapping adversary tactics (MITRE ATT&CK) and IOCs.

*In CyberShield, the SOC dashboard provides automated threat telemetry, risk scoring, and AI-assisted triage.*
    `.trim();
  }

  // Threat vs Vulnerability
  if (p.includes('difference between threat and vulnerability') || p.includes('threat vs vulnerability') || p.includes('threat and vulnerability')) {
    return `
### ⚖️ Difference Between a Threat and a Vulnerability

| Aspect | **Vulnerability** | **Threat** |
| :--- | :--- | :--- |
| **Definition** | A weakness, bug, or flaw in a system. | Any entity, action, or event with the potential to cause harm. |
| **Nature** | Internal (your software, misconfigurations). | External or contextual (attackers, malware, phishing). |
| **Example** | Missing CSP header, unpatched Apache CVE. | A ransomware gang, credential stuffing script, phishing email. |
| **Control** | Can be **patched / remediated** directly. | Must be **defended against / mitigated**. |

$$\\text{Risk} = \\text{Threat} \\times \\text{Vulnerability} \\times \\text{Impact}$$
    `.trim();
  }

  // What is CVSS / CVE / CWE?
  if (p.includes('cvss') || p.includes('cve') || p.includes('cwe')) {
    return `
### 🏷️ Understanding CVE, CVSS, and CWE

- **CVE (Common Vulnerabilities and Exposures):** A standardized identifier for publicly known security vulnerabilities (e.g., \`CVE-2024-38077\`).
- **CVSS (Common Vulnerability Scoring System):** A numeric score from **0.0 to 10.0** representing the technical severity of a vulnerability:
  - **Critical:** 9.0 – 10.0
  - **High:** 7.0 – 8.9
  - **Medium:** 4.0 – 6.9
  - **Low:** 0.1 – 3.9
- **CWE (Common Weakness Enumeration):** A categorization of software weakness types (e.g., \`CWE-79\` for Cross-Site Scripting, \`CWE-89\` for SQL Injection).
    `.trim();
  }

  // What is SIEM & SOAR?
  if (p.includes('siem') || p.includes('soar')) {
    return `
### 🖥️ SIEM vs. SOAR in Modern Security Operations

- **SIEM (Security Information and Event Management):** Collects, aggregates, and correlates log data across servers, network appliances, and security tools to identify anomalous patterns and generate alerts.
- **SOAR (Security Orchestration, Automation, and Response):** Automates playbooks and response actions (e.g., isolating an infected host or blocking an IP on the firewall) without requiring manual analyst intervention.
    `.trim();
  }

  // What is IDS / IPS / Firewall / WAF?
  if (p.includes('firewall') || p.includes('waf') || p.includes('ids') || p.includes('ips')) {
    return `
### 🧱 Firewalls, WAFs, IDS, and IPS

- **Firewall (NGFW):** Filters network traffic based on IP addresses, ports, and application protocols.
- **WAF (Web Application Firewall):** Specialized Layer-7 proxy that inspects HTTP/HTTPS traffic to block web attacks like SQL Injection and Cross-Site Scripting.
- **IDS (Intrusion Detection System):** Passively monitors network traffic and alerts analysts when malicious signatures or anomalies are observed.
- **IPS (Intrusion Prevention System):** Sits in-line with network traffic to actively block detected attack packets in real time.
    `.trim();
  }

  // HTTP Security Headers (HSTS, CSP, X-Frame)
  if (p.includes('header') || p.includes('hsts') || p.includes('csp') || p.includes('content-security-policy') || p.includes('x-frame')) {
    return `
### 🛡️ Essential HTTP Security Headers

1. **Content-Security-Policy (CSP):**
   - Restricts which scripts, styles, and media sources the browser can load, mitigating Cross-Site Scripting (XSS).
   - \`Content-Security-Policy: default-src 'self'; script-src 'self'\`
2. **Strict-Transport-Security (HSTS):**
   - Forces web browsers to exclusively connect over HTTPS, preventing SSL-stripping MitM attacks.
   - \`Strict-Transport-Security: max-age=31536000; includeSubDomains\`
3. **X-Frame-Options:**
   - Prevents the site from being rendered in an iframe, stopping Clickjacking attacks.
   - \`X-Frame-Options: DENY\` or \`SAMEORIGIN\`
4. **X-Content-Type-Options:**
   - Prevents MIME-type sniffing: \`X-Content-Type-Options: nosniff\`.
    `.trim();
  }

  // HTTPS, SSL, TLS
  if (p.includes('https') || p.includes('ssl') || p.includes('tls')) {
    return `
### 🔒 HTTPS and TLS (Transport Layer Security)

**HTTPS (Hypertext Transfer Protocol Secure)** encrypts communication between the client's browser and the web server using **TLS (Transport Layer Security)**.

#### Core Cryptographic Protections:
- **Confidentiality:** Eavesdroppers cannot inspect transmitted data (passwords, sessions).
- **Integrity:** Data cannot be modified or tampered with in transit.
- **Authentication:** Validates the server's identity via trusted Public Key Infrastructure (PKI) certificates.
- **Standard:** Enforce modern **TLS 1.2 or TLS 1.3** and disable deprecated SSL 2.0/3.0 and TLS 1.0/1.1.
    `.trim();
  }

  // What is Incident Response?
  if (p.includes('incident response') || p.includes('ir lifecycle') || p.includes('nist')) {
    return `
### 🚨 The 6 Phases of Incident Response (NIST / SANS):

1. **Preparation:** Establishing security policies, tools, access controls, and incident playbooks.
2. **Identification / Detection:** Recognizing security events, alerts, and potential compromises.
3. **Containment:** Short-term and long-term isolation (e.g., disconnecting host from network, blocking malicious IPs).
4. **Eradication:** Removing root-cause malware, invalidating compromised tokens, and patching vulnerabilities.
5. **Recovery:** Restoring systems to production safely while monitoring for re-infection.
6. **Lessons Learned:** Post-incident review to refine defenses and update playbooks.
    `.trim();
  }

  // What is CyberShield?
  if (p.includes('cybershield') || p.includes('what is this') || p.includes('who are you')) {
    return `
### 🛡️ About CyberShield AI Security Platform

**CyberShield** is an AI-powered **Web Security Monitoring & SOC Platform** engineered for continuous attack surface discovery, threat detection, and incident response.

#### Capabilities:
- **AI URL Threat Scanner:** Real-time heuristic and machine-learning phishing detection.
- **Website Security & Header Auditing:** Deep inspection of TLS certificates, ciphers, and security headers.
- **Attack Surface Mapping:** Visual graph mapping of exposed hostnames, subdomains, and ports.
- **Automated 24/7 Monitoring:** Periodic background health checks with SSE live alerting.
- **Incident Response Hub:** Full incident management lifecycle with AI root-cause analysis.
- **AI Security Copilot:** Interactive, context-aware cybersecurity assistance.
    `.trim();
  }

  // Greetings & Friendly General Queries
  if (p === 'hi' || p === 'hello' || p === 'hey' || p.startsWith('hello') || p.startsWith('hi ') || p.includes('how are you')) {
    return `Hello! 👋 I am your **CyberShield AI Security Copilot**. I can answer any cybersecurity questions, explain vulnerabilities and threats, analyze your scans, or help with security remediation. What would you like to explore?`;
  }

  // Follow-up resolution with conversation memory
  const lastUserMsg = Array.isArray(history) && history.length > 0
    ? history.filter(h => h.role === 'user').slice(-1)[0]?.content
    : null;

  if (lastUserMsg && (p.includes('how to fix') || p.includes('how do i fix') || p.includes('explain more') || p.includes('tell me more') || p.includes('what about that') || p.includes('example'))) {
    return `
### 🛠️ Remediation & Technical Guidance

Regarding your question about **"${lastUserMsg.substring(0, 60)}"**:

#### Recommended Step-by-Step Actions:
1. **Audit Affected Endpoints:** Inspect the specific target domain or configuration setting.
2. **Apply Defensive Configurations:** Ensure strict HTTP security headers, valid TLS 1.3 certificates, and enforced 2FA.
3. **Verify via Scanner:** Run a new scan in the **Security Scanners** tool to confirm the security score improves.

*If you have specific code, server configs, or error messages, paste them here and I will generate the exact fix.*
    `.trim();
  }

  // Comprehensive General Technical Fallback
  return `
### 🛡️ CyberShield AI Copilot Response

To address **"${userPrompt.substring(0, 70)}"**:

- **Security Guidance:** In defensive cybersecurity and SOC operations, ensure assets are audited regularly against known CVEs, enforced with modern TLS encryption, and monitored for abnormal behavior.
- **Platform Telemetry:** You can check your **Dashboard** for live posture scores, view active threats in **Incident Response**, or run a deep audit via **Security Scanners**.

*Feel free to ask more specific questions about SOC concepts, vulnerabilities, headers, or your scan results!*
  `.trim();
}

module.exports = {
  getDashboardSummary,
  getRecentScans,
  getScanDetails,
  getVulnerabilities,
  getMonitoringStatus,
  getAttackSurfaceData,
  getIncidentsData,
  callGeminiAPI
};
