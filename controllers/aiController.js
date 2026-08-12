/**
 * CyberShield — AI Security Copilot Controller
 *
 * Handles rate-limited, authenticated requests for AI Security Copilot features.
 * Connects to controlled data retrieval tools and Gemini API.
 */

const {
  getDashboardSummary,
  getRecentScans,
  getScanDetails,
  getVulnerabilities,
  getMonitoringStatus,
  getAttackSurfaceData,
  callGeminiAPI
} = require('../utils/geminiCopilot');
const Log = require('../models/Log');

// @desc    Natural Language Security Chat
// @route   POST /api/ai/chat
// @access  Private
exports.chat = async (req, res, next) => {
  try {
    const { prompt, pageContext = 'dashboard' } = req.body;
    const userId = req.user._id;
    const isAdmin = req.user.role === 'admin';

    if (!prompt || typeof prompt !== 'string' || prompt.trim() === '') {
      return res.status(400).json({
        success: false,
        error: 'Please enter a valid security question or prompt.'
      });
    }

    const cleanPrompt = prompt.trim();

    // Audit Log (Do not store tokens/passwords)
    try {
      await Log.create({
        user: userId,
        username: req.user.username,
        action: 'AI_COPILOT_CHAT',
        details: `Page: ${pageContext} | Prompt: ${cleanPrompt.substring(0, 80)}...`,
        status: 'SUCCESS'
      });
    } catch (e) {}

    // Intent Detection & Controlled Tool Selection
    let contextData = {};
    const lowerPrompt = cleanPrompt.toLowerCase();

    if (lowerPrompt.includes('score') || lowerPrompt.includes('why is my score')) {
      contextData.summary = await getDashboardSummary(userId, isAdmin);
    } else if (lowerPrompt.includes('vulnerability') || lowerPrompt.includes('vulnerabilities')) {
      contextData.vulnerabilities = await getVulnerabilities(userId, isAdmin);
    } else if (lowerPrompt.includes('attack surface') || lowerPrompt.includes('asset')) {
      contextData.attackSurface = await getAttackSurfaceData(userId, isAdmin);
    } else if (lowerPrompt.includes('monitoring') || lowerPrompt.includes('monitored')) {
      contextData.monitoring = await getMonitoringStatus(userId, isAdmin);
    } else if (lowerPrompt.includes('scan') || lowerPrompt.includes('latest scan')) {
      contextData.recentScans = await getRecentScans(userId, 5, isAdmin);
    } else {
      contextData.summary = await getDashboardSummary(userId, isAdmin);
      contextData.recentScans = await getRecentScans(userId, 3, isAdmin);
    }

    const responseText = await callGeminiAPI(cleanPrompt, contextData, pageContext);

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
        stats: summary,
        timestamp: new Date()
      }
    });
  } catch (err) {
    next(err);
  }
};

// @desc    AI Security Score Analysis
// @route   POST /api/ai/explain-score
// @access  Private
exports.explainScore = async (req, res, next) => {
  try {
    const userId = req.user._id;
    const isAdmin = req.user.role === 'admin';

    const summary = await getDashboardSummary(userId, isAdmin);
    const recentScans = await getRecentScans(userId, 5, isAdmin);

    const contextData = { summary, recentScans };
    const scoreAnalysis = await callGeminiAPI('Explain my Security Score and detailed risk metrics.', contextData, 'scanner');

    res.status(200).json({
      success: true,
      data: {
        analysis: scoreAnalysis,
        score: summary.avgSecurityScore,
        timestamp: new Date()
      }
    });
  } catch (err) {
    next(err);
  }
};

// @desc    Explain Specific Scan Result with AI
// @route   POST /api/ai/explain-scan
// @access  Private
exports.explainScan = async (req, res, next) => {
  try {
    const { scanId } = req.body;
    const userId = req.user._id;
    const isAdmin = req.user.role === 'admin';

    let scanData = null;
    if (scanId) {
      scanData = await getScanDetails(scanId, userId, isAdmin);
    }

    if (!scanData) {
      const recent = await getRecentScans(userId, 1, isAdmin);
      if (recent.length > 0) {
        scanData = await getScanDetails(recent[0].id, userId, isAdmin);
      }
    }

    if (!scanData) {
      return res.status(404).json({
        success: false,
        error: "I don't have enough current CyberShield data to analyze."
      });
    }

    const explanation = await callGeminiAPI(`Explain the security scan details for asset ${scanData.target}`, scanData, 'scanner');

    res.status(200).json({
      success: true,
      data: {
        scan: scanData,
        explanation,
        timestamp: new Date()
      }
    });
  } catch (err) {
    next(err);
  }
};

// @desc    Explain Specific Vulnerability
// @route   POST /api/ai/explain-vulnerability
// @access  Private
exports.explainVulnerability = async (req, res, next) => {
  try {
    const { vulnerabilityTitle, scanId } = req.body;
    const userId = req.user._id;
    const isAdmin = req.user.role === 'admin';

    const vulns = await getVulnerabilities(userId, isAdmin);

    let targetVuln = vulns.find(v => v.title.toLowerCase().includes((vulnerabilityTitle || '').toLowerCase()));
    if (!targetVuln && vulns.length > 0) {
      targetVuln = vulns[0];
    }

    const prompt = targetVuln
      ? `Explain the vulnerability "${targetVuln.title}" affecting ${targetVuln.target}`
      : `Explain top security vulnerabilities affecting CyberShield web assets`;

    const explanation = await callGeminiAPI(prompt, { vulnerability: targetVuln, allVulnerabilities: vulns }, 'vulnerabilities');

    res.status(200).json({
      success: true,
      data: {
        vulnerability: targetVuln || null,
        explanation,
        timestamp: new Date()
      }
    });
  } catch (err) {
    next(err);
  }
};

// @desc    AI Security Investigation
// @route   POST /api/ai/investigate
// @access  Private
exports.investigate = async (req, res, next) => {
  try {
    const { scanId, asset } = req.body;
    const userId = req.user._id;
    const isAdmin = req.user.role === 'admin';

    const summary = await getDashboardSummary(userId, isAdmin);
    const recentScans = await getRecentScans(userId, 5, isAdmin);
    const attackSurface = await getAttackSurfaceData(userId, isAdmin);
    const vulns = await getVulnerabilities(userId, isAdmin);

    const contextData = { summary, recentScans, attackSurface, vulnerabilities: vulns };
    const prompt = asset
      ? `Perform a full SOC security investigation for asset ${asset}`
      : `Perform a full SOC security investigation across active CyberShield security data`;

    const investigationReport = await callGeminiAPI(prompt, contextData, 'investigation');

    res.status(200).json({
      success: true,
      data: {
        investigation: investigationReport,
        timestamp: new Date()
      }
    });
  } catch (err) {
    next(err);
  }
};

// @desc    Generate Full AI Security Audit Report
// @route   POST /api/ai/generate-report
// @access  Private
exports.generateReport = async (req, res, next) => {
  try {
    const userId = req.user._id;
    const isAdmin = req.user.role === 'admin';

    const summary = await getDashboardSummary(userId, isAdmin);
    const recentScans = await getRecentScans(userId, 10, isAdmin);
    const vulnerabilities = await getVulnerabilities(userId, isAdmin);
    const attackSurface = await getAttackSurfaceData(userId, isAdmin);

    const contextData = { summary, recentScans, vulnerabilities, attackSurface };
    const reportText = await callGeminiAPI('Generate an Executive Security Audit Report summarizing posture, findings, and remediation priority.', contextData, 'reports');

    res.status(200).json({
      success: true,
      data: {
        report: reportText,
        summary,
        generatedAt: new Date()
      }
    });
  } catch (err) {
    next(err);
  }
};
