const Scan = require('../models/Scan');
const { predictUrlPhishing } = require('../utils/aiClient');

// @desc    Process AI Chat message
// @route   POST /api/copilot/chat
exports.processChat = async (req, res) => {
  try {
    const { message } = req.body;
    
    if (!message) {
      return res.status(400).json({ success: false, error: 'Message is required' });
    }

    // 1. Retrieve the user's latest scans for context
    let recentScans = [];
    if (req.user) {
      recentScans = await Scan.find({ user: req.user._id })
                              .sort({ createdAt: -1 })
                              .limit(3);
    }
    
    // 2. Build the context string
    let contextStr = "User has no recent scans.";
    if (recentScans.length > 0) {
      const latest = recentScans[0];
      contextStr = `Latest scan was on ${latest.target}. Score: ${100 - latest.riskScore}/100. Status: ${latest.status}. `;
      if (latest.recommendations && latest.recommendations.length > 0) {
        contextStr += `Top recommendation: ${latest.recommendations[0]}. `;
      }
    }

    // 3. Simple rule-based/AI heuristic response generation
    const q = message.toLowerCase();
    let reply = "";
    
    if (q.includes('score') && q.includes('low')) {
      reply = `Based on your recent data (${contextStr}), low scores are typically caused by missing strict HTTP security headers (like HSTS or CSP) or invalid SSL certificates. Check the "Vulnerabilities" tab for specific remediation steps.`;
    } else if (q.includes('fix first')) {
      reply = `Always prioritize Critical risk items. Looking at your profile (${contextStr}), I recommend starting there. Ensure your SSL certificate is valid and enforce HTTPS traffic.`;
    } else if (q.includes('what changed')) {
      reply = `To see exact changes, navigate to the "Security Scanners" tab and view the Historical Diff. It tracks score drift, header modifications, and resolved vulnerabilities.`;
    } else if (q.includes('vulnerability')) {
      reply = `A vulnerability is a weakness in your web application (like an exposed server banner or missing CSP). You can use our detailed scanner to identify these exactly. ${contextStr}`;
    } else if (q.includes('improve')) {
      reply = `To improve your security score, you should: 1. Implement an SSL certificate. 2. Set HSTS headers. 3. Define a strict Content Security Policy (CSP). 4. Prevent clickjacking with X-Frame-Options.`;
    } else {
      reply = `I am CyberBot, analyzing your request: "${message}". Context: ${contextStr}. For a deep dive into specific threats, please trigger a manual scan from the Security Tools menu.`;
    }

    res.status(200).json({
      success: true,
      reply: reply
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
};
