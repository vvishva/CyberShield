/**
 * CyberShield — AI Security Copilot Controller
 *
 * Handles rate-limited, authenticated requests for AI Security Copilot features.
 * Connects to controlled data retrieval tools and Gemini API with conversational memory.
 */

const {
  getDashboardSummary,
  getRecentScans,
  getScanDetails,
  getVulnerabilities,
  getMonitoringStatus,
  getAttackSurfaceData,
  getIncidentsData,
  callGeminiAPI
} = require('../utils/geminiCopilot');
const Log = require('../models/Log');

// @desc    Natural Language Security Chat with Conversation Memory
// @route   POST /api/ai/chat
// @access  Private
exports.chat = async (req, res, next) => {
  try {
    const { prompt, history = [], pageContext = 'dashboard' } = req.body;
    const userId = req.user._id;
    const isAdmin = req.user.role === 'admin';

    if (!prompt || typeof prompt !== 'string' || prompt.trim() === '') {
      return res.status(400).json({
        success: false,
        error: 'Please enter a valid security question or prompt.'
      });
    }

    const cleanPrompt = prompt.trim();

    // Audit Log
    try {
      await Log.create({
        user: userId,
        username: req.user.username,
        action: 'AI_COPILOT_CHAT',
        details: `Page: ${pageContext} | Prompt: ${cleanPrompt.substring(0, 80)}...`,
        status: 'SUCCESS'
      });
    } catch (e) {}

    // Controlled Tool Selection based on query intent
    let contextData = {};
    const lowerPrompt = cleanPrompt.toLowerCase();

    if (lowerPrompt.includes('incident') || lowerPrompt.includes('unresolved') || lowerPrompt.includes('containment') || lowerPrompt.includes('triage')) {
      contextData.incidents = await getIncidentsData(userId, isAdmin);
      contextData.summary = await getDashboardSummary(userId, isAdmin);
    } else if (lowerPrompt.includes('score') || lowerPrompt.includes('why is my score') || lowerPrompt.includes('risk score') || lowerPrompt.includes('risk level')) {
      contextData.summary = await getDashboardSummary(userId, isAdmin);
      contextData.vulnerabilities = await getVulnerabilities(userId, isAdmin);
      contextData.incidents = await getIncidentsData(userId, isAdmin);
    } else if (lowerPrompt.includes('vulnerability') || lowerPrompt.includes('vulnerabilities') || lowerPrompt.includes('fix first') || lowerPrompt.includes('cve')) {
      contextData.vulnerabilities = await getVulnerabilities(userId, isAdmin);
      contextData.recentScans = await getRecentScans(userId, 5, isAdmin);
    } else if (lowerPrompt.includes('dangerous asset') || lowerPrompt.includes('attack surface') || lowerPrompt.includes('asset') || lowerPrompt.includes('exposure')) {
      contextData.attackSurface = await getAttackSurfaceData(userId, isAdmin);
      contextData.monitoring = await getMonitoringStatus(userId, isAdmin);
      contextData.recentScans = await getRecentScans(userId, 5, isAdmin);
    } else if (lowerPrompt.includes('threat') || lowerPrompt.includes('phishing') || lowerPrompt.includes('summarize today')) {
      contextData.recentScans = await getRecentScans(userId, 5, isAdmin);
      contextData.incidents = await getIncidentsData(userId, isAdmin);
      contextData.summary = await getDashboardSummary(userId, isAdmin);
    } else if (lowerPrompt.includes('monitoring') || lowerPrompt.includes('monitored')) {
      contextData.monitoring = await getMonitoringStatus(userId, isAdmin);
    } else if (lowerPrompt.includes('scan') || lowerPrompt.includes('latest scan')) {
      contextData.recentScans = await getRecentScans(userId, 5, isAdmin);
    } else {
      contextData.summary = await getDashboardSummary(userId, isAdmin);
      contextData.recentScans = await getRecentScans(userId, 3, isAdmin);
      contextData.incidents = await getIncidentsData(userId, isAdmin);
    }

    const responseText = await callGeminiAPI(cleanPrompt, contextData, pageContext, history);

    res.status(200).json({
      success: true,
      data: {
        response: responseText,
        pageContext,
        timestamp: new Date()
      }
    });
  } catch (err) {
    next(err);
  }
};

// @desc    Get Today's AI SOC Security Briefing
// @route   GET /api/ai/briefing
// @access  Private
exports.getBriefing = async (req, res, next) => {
  try {
    const userId = req.user._id;
    const isAdmin = req.user.role === 'admin';

    const summary = await getDashboardSummary(userId, isAdmin);
    const recentScans = await getRecentScans(userId, 5, isAdmin);
    const vulnerabilities = await getVulnerabilities(userId, isAdmin);

    const contextData = { summary, recentScans, vulnerabilities };
    const briefingText = await callGeminiAPI('Give me today\'s SOC Briefing summary.', contextData, 'dashboard');

    res.status(200).json({
      success: true,
      data: {
        briefing: briefingText,
        timestamp: new Date()
      }
    });
  } catch (err) {
    next(err);
  }
};

// @desc    AI Security Score Explainer
// @route   POST /api/ai/explain-score
// @access  Private
exports.explainScore = async (req, res, next) => {
  try {
    const userId = req.user._id;
    const isAdmin = req.user.role === 'admin';
    const { scanId } = req.body;

    let scanData = null;
    if (scanId) {
      scanData = await getScanDetails(scanId, userId, isAdmin);
    }
    const summary = await getDashboardSummary(userId, isAdmin);
    const contextData = scanData ? { scan: scanData, summary } : { summary };

    const explanationText = await callGeminiAPI('Explain my overall security score, positive security controls, and key risk factors.', contextData, 'scanner');

    res.status(200).json({
      success: true,
      data: {
        explanation: explanationText,
        timestamp: new Date()
      }
    });
  } catch (err) {
    next(err);
  }
};

// @desc    AI Scan Explainer
// @route   POST /api/ai/explain-scan
// @access  Private
exports.explainScan = async (req, res, next) => {
  try {
    const userId = req.user._id;
    const isAdmin = req.user.role === 'admin';
    const { scanId } = req.body;

    let scanData = null;
    if (scanId) {
      scanData = await getScanDetails(scanId, userId, isAdmin);
    } else {
      const recent = await getRecentScans(userId, 1, isAdmin);
      if (recent.length > 0) scanData = await getScanDetails(recent[0].id, userId, isAdmin);
    }

    if (!scanData) {
      return res.status(404).json({
        success: false,
        error: 'No scan data found to analyze.'
      });
    }

    const explanationText = await callGeminiAPI(`Explain the scan findings for website target: ${scanData.target}.`, { scan: scanData }, 'scanner');

    res.status(200).json({
      success: true,
      data: {
        explanation: explanationText,
        scanId: scanData.id,
        target: scanData.target,
        timestamp: new Date()
      }
    });
  } catch (err) {
    next(err);
  }
};

// @desc    AI Vulnerability Explainer & Remediation Generator
// @route   POST /api/ai/explain-vulnerability
// @access  Private
exports.explainVulnerability = async (req, res, next) => {
  try {
    const userId = req.user._id;
    const isAdmin = req.user.role === 'admin';
    const { vulnerabilityTitle, vulnerabilityDesc, severity, target } = req.body;

    let explanationText;
    if (vulnerabilityTitle) {
      const prompt = `Analyze and provide a complete technical remediation plan for this vulnerability:
- Title: ${vulnerabilityTitle}
- Severity: ${severity || 'HIGH'}
- Target Asset: ${target || 'Web Application'}
- Details: ${vulnerabilityDesc || 'Security vulnerability'}

Provide:
1. Root Cause Explanation
2. Exploit Scenario & Threat Impact
3. Step-by-Step Technical Fix & Exact Configuration / Code snippet (e.g. Nginx, Apache, Node.js headers)`;

      explanationText = await callGeminiAPI(prompt, { vulnerability: { title: vulnerabilityTitle, severity, target } }, 'vulnerabilities');
    } else {
      const vulnerabilities = await getVulnerabilities(userId, isAdmin);
      explanationText = await callGeminiAPI('Explain active vulnerabilities across my scanned web targets and provide technical remediation advice.', { vulnerabilities }, 'vulnerabilities');
    }

    res.status(200).json({
      success: true,
      data: {
        explanation: explanationText,
        timestamp: new Date()
      }
    });
  } catch (err) {
    next(err);
  }
};

// @desc    AI Threat Triage & Investigation
// @route   POST /api/ai/investigate
// @access  Private
exports.investigate = async (req, res, next) => {
  try {
    const userId = req.user._id;
    const isAdmin = req.user.role === 'admin';

    const recentScans = await getRecentScans(userId, 10, isAdmin);
    const vulnerabilities = await getVulnerabilities(userId, isAdmin);
    const attackSurface = await getAttackSurfaceData(userId, isAdmin);

    const contextData = { recentScans, vulnerabilities, attackSurface };
    const investigationText = await callGeminiAPI('Perform threat triage and security investigation across my environment. Identify top priorities.', contextData, 'investigation');

    res.status(200).json({
      success: true,
      data: {
        investigation: investigationText,
        timestamp: new Date()
      }
    });
  } catch (err) {
    next(err);
  }
};

// @desc    AI Security Audit Report Generator
// @route   POST /api/ai/generate-report
// @access  Private
exports.generateReport = async (req, res, next) => {
  try {
    const userId = req.user._id;
    const isAdmin = req.user.role === 'admin';

    const summary = await getDashboardSummary(userId, isAdmin);
    const recentScans = await getRecentScans(userId, 10, isAdmin);
    const vulnerabilities = await getVulnerabilities(userId, isAdmin);
    const monitoring = await getMonitoringStatus(userId, isAdmin);

    const contextData = { summary, recentScans, vulnerabilities, monitoring };
    const reportText = await callGeminiAPI('Generate an Executive Security Audit Report summarizing posture, findings, and mitigation roadmap.', contextData, 'reports');

    res.status(200).json({
      success: true,
      data: {
        report: reportText,
        timestamp: new Date()
      }
    });
  } catch (err) {
    next(err);
  }
};
