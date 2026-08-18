/**
 * CyberShield — Incident Response Controller
 * Manages full lifecycle of security incidents, triage workflows, analyst notes, and AI response analysis.
 */

const Incident = require('../models/Incident');
const Log = require('../models/Log');
const { callGeminiAPI } = require('../utils/geminiCopilot');

// Helper to seed realistic incidents if new user has none
async function seedInitialIncidents(userId, username) {
  const samples = [
    {
      incidentId: `INC-${new Date().getFullYear()}-8921`,
      user: userId,
      title: 'Active Phishing Impersonation Host Detected',
      severity: 'CRITICAL',
      status: 'Investigating',
      relatedAsset: 'auth.portal-login.xyz',
      relatedThreat: 'Credential Harvesting Engine',
      relatedVulnerability: 'Homograph Domain Spoofing',
      assignedAnalyst: username || 'Lead SOC Analyst',
      description: 'Threat intelligence sentinel detected an unauthorized deceptive clone targeting user credential forms.',
      impact: 'Immediate credential theft risk for customers entering authentication parameters.',
      evidence: [
        { key: 'Target URL', value: 'https://auth.portal-login.xyz/login', detail: 'Hosted on rogue ASN 48211' },
        { key: 'Heuristic Match', value: '98.4% Phishing Confidence', detail: 'Matched known brand asset signature' },
        { key: 'SSL Issuer', value: "Let's Encrypt (Issued today)", detail: 'Newly minted short-lived certificate' }
      ],
      aiAnalysis: 'High-confidence brand impersonation attack. Attackers configured a replica login portal to intercept OAuth credentials.',
      recommendedResponse: '1. Initiate DNS registrar takedown notice via APWG / Google Safe Browsing.\n2. Block egress network traffic to IP in perimeter firewall.\n3. Invalidate active session tokens for accounts targeted.',
      investigationNotes: [
        { author: 'Automated AI Sentinel', note: 'Threat detected during continuous automated surface scan.', timestamp: new Date(Date.now() - 3600000) },
        { author: username || 'SOC Analyst', note: 'Domain flagged and placed under active containment triage.', timestamp: new Date(Date.now() - 1800000) }
      ],
      timeline: [
        { action: 'Threat Detected', detail: 'AI Sentinel flagged rogue clone URL', user: 'Sentinel Engine', timestamp: new Date(Date.now() - 3600000) },
        { action: 'Incident Escalated', detail: 'Severity set to CRITICAL and analyst assigned', user: 'System', timestamp: new Date(Date.now() - 3000000) },
        { action: 'Status Updated', detail: 'Moved to Investigating state', user: username || 'Analyst', timestamp: new Date(Date.now() - 1800000) }
      ],
      detectionTime: new Date(Date.now() - 3600000),
      lastUpdated: new Date()
    },
    {
      incidentId: `INC-${new Date().getFullYear()}-8419`,
      user: userId,
      title: 'Missing Content-Security-Policy & Frame Exposure',
      severity: 'HIGH',
      status: 'New',
      relatedAsset: 'api.production.internal',
      relatedVulnerability: 'Clickjacking & XSS Exposure',
      relatedThreat: 'UI Redress & Inline Script Injection',
      assignedAnalyst: 'Automated Policy Engine',
      description: 'Web server headers omitted Content-Security-Policy and X-Frame-Options, allowing clickjacking framing attacks.',
      impact: 'Vulnerability permits malicious actors to embed the endpoint in transparent iframes.',
      evidence: [
        { key: 'Header Check', value: 'CSP Missing', detail: 'No Content-Security-Policy HTTP response header' },
        { key: 'Frame Check', value: 'X-Frame-Options Missing', detail: 'SAMEORIGIN or DENY not configured' }
      ],
      aiAnalysis: 'Missing defense-in-depth headers leaves endpoint vulnerable to cross-site framing attacks and untrusted script execution.',
      recommendedResponse: 'Deploy HTTP response headers: `Content-Security-Policy: default-src \'self\';` and `X-Frame-Options: DENY`.',
      investigationNotes: [],
      timeline: [
        { action: 'Audit Completed', detail: 'Header verification audit flagged missing headers', user: 'Security Scanner', timestamp: new Date(Date.now() - 7200000) },
        { action: 'Incident Logged', detail: 'Created HIGH severity configuration incident', user: 'System', timestamp: new Date(Date.now() - 7200000) }
      ],
      detectionTime: new Date(Date.now() - 7200000),
      lastUpdated: new Date()
    },
    {
      incidentId: `INC-${new Date().getFullYear()}-7730`,
      user: userId,
      title: 'SSL/TLS Certificate Cipher Downgrade Warning',
      severity: 'MEDIUM',
      status: 'Contained',
      relatedAsset: 'gateway.cloud-network.io',
      relatedVulnerability: 'TLS 1.0/1.1 Legacy Protocols Enabled',
      relatedThreat: 'Man-in-the-Middle Cipher Downgrade',
      assignedAnalyst: username || 'SOC Analyst',
      description: 'Perimeter TLS audit revealed legacy cipher suites supported on ingress gateway.',
      impact: 'Deprecated cryptographic protocols can be negotiated by legacy clients.',
      evidence: [
        { key: 'Protocol Audit', value: 'TLS 1.0 Enabled', detail: 'CBC ciphers present in handshake list' }
      ],
      aiAnalysis: 'Legacy cipher support weakens PFS (Perfect Forward Secrecy). Modern standards require TLS 1.2 minimum.',
      recommendedResponse: 'Disable TLS 1.0 and TLS 1.1 in Nginx/Apache configuration, enforce modern TLS 1.3 suites only.',
      investigationNotes: [
        { author: username || 'SOC Analyst', note: 'Gateway TLS profile updated to intermediate modern suite.', timestamp: new Date(Date.now() - 14400000) }
      ],
      timeline: [
        { action: 'Audit Completed', detail: 'Detected legacy TLS ciphers', user: 'SSL Audit Engine', timestamp: new Date(Date.now() - 86400000) },
        { action: 'Contained', detail: 'Ingress rule modified to reject TLS 1.0', user: username || 'Analyst', timestamp: new Date(Date.now() - 14400000) }
      ],
      detectionTime: new Date(Date.now() - 86400000),
      lastUpdated: new Date()
    },
    {
      incidentId: `INC-${new Date().getFullYear()}-6510`,
      user: userId,
      title: 'Anomalous Session Origin & Velocity Detected',
      severity: 'LOW',
      status: 'Resolved',
      relatedAsset: 'CyberShield Auth Gateway',
      relatedVulnerability: 'Brute Force / Credential Stuffing Attempt',
      relatedThreat: 'Automated Account Enumeration',
      assignedAnalyst: 'Heuristic Sentinel',
      description: 'Multiple failed authentication requests detected from rotating IP block within 60 seconds.',
      impact: 'Automated bot attempts rate-limited before unauthorized access occurred.',
      evidence: [
        { key: 'Source IP Count', value: '14 Unique IPs', detail: 'Rate limiting threshold engaged' },
        { key: 'Firewall Action', value: 'IP Range Blocked (24h)', detail: 'Temporary CIDR ban applied' }
      ],
      aiAnalysis: 'Coordinated credential stuffing attempt safely mitigated by adaptive rate limiting.',
      recommendedResponse: 'Monitor auth telemetry for 48 hours. Ensure 2FA remains enforced for all user accounts.',
      investigationNotes: [
        { author: 'Heuristic Sentinel', note: 'All malicious requests dropped with 429 status code.', timestamp: new Date(Date.now() - 172800000) }
      ],
      timeline: [
        { action: 'Anomaly Detected', detail: 'High velocity auth failures flagged', user: 'Heuristic Engine', timestamp: new Date(Date.now() - 172800000) },
        { action: 'Resolved', detail: 'CIDR blocked and attack subsided', user: 'System', timestamp: new Date(Date.now() - 86400000) }
      ],
      detectionTime: new Date(Date.now() - 172800000),
      lastUpdated: new Date()
    }
  ];

  try {
    await Incident.insertMany(samples);
  } catch (e) {}
}

// @desc    Get all Incidents with filtering
// @route   GET /api/incidents
exports.getIncidents = async (req, res) => {
  try {
    const userId = req.user ? req.user._id : null;
    const { status, severity, asset, search } = req.query;

    const query = {};
    if (userId && req.user.role !== 'admin') {
      query.user = userId;
    }

    if (status && status !== 'all') query.status = status;
    if (severity && severity !== 'all') query.severity = severity.toUpperCase();
    if (asset && asset !== 'all') query.relatedAsset = new RegExp(asset, 'i');
    if (search) {
      query.$or = [
        { title: new RegExp(search, 'i') },
        { incidentId: new RegExp(search, 'i') },
        { relatedAsset: new RegExp(search, 'i') },
        { description: new RegExp(search, 'i') }
      ];
    }

    let incidents = await Incident.find(query).sort({ lastUpdated: -1 }).lean();

    // Auto-seed sample incidents for new users
    if (incidents.length === 0 && !status && !severity && !search && userId) {
      await seedInitialIncidents(userId, req.user.username);
      incidents = await Incident.find(query).sort({ lastUpdated: -1 }).lean();
    }

    const counts = {
      total: incidents.length,
      new: incidents.filter(i => i.status === 'New').length,
      investigating: incidents.filter(i => i.status === 'Investigating').length,
      contained: incidents.filter(i => i.status === 'Contained').length,
      resolved: incidents.filter(i => i.status === 'Resolved').length,
      closed: incidents.filter(i => i.status === 'Closed').length,
      critical: incidents.filter(i => i.severity === 'CRITICAL').length,
      high: incidents.filter(i => i.severity === 'HIGH').length
    };

    res.status(200).json({
      success: true,
      counts,
      data: incidents
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
};

// @desc    Get Single Incident Details
// @route   GET /api/incidents/:id
exports.getIncidentById = async (req, res) => {
  try {
    const { id } = req.params;
    const query = { $or: [{ _id: id.match(/^[0-9a-fA-F]{24}$/) ? id : null }, { incidentId: id }].filter(Boolean) };

    const incident = await Incident.findOne(query).lean();
    if (!incident) {
      return res.status(404).json({ success: false, error: 'Incident not found.' });
    }

    res.status(200).json({
      success: true,
      data: incident
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
};

// @desc    Create New Incident
// @route   POST /api/incidents
exports.createIncident = async (req, res) => {
  try {
    const { title, severity, relatedAsset, relatedVulnerability, relatedThreat, description, impact, evidence, scanId } = req.body;

    if (!title || !description) {
      return res.status(400).json({ success: false, error: 'Title and description are required.' });
    }

    const incidentId = `INC-${new Date().getFullYear()}-${Math.floor(1000 + Math.random() * 9000)}`;
    const now = new Date();

    const incident = await Incident.create({
      incidentId,
      user: req.user ? req.user._id : null,
      title,
      severity: (severity || 'MEDIUM').toUpperCase(),
      status: 'New',
      relatedAsset: relatedAsset || 'Web Application',
      relatedVulnerability: relatedVulnerability || '',
      relatedThreat: relatedThreat || '',
      scanId: scanId || null,
      assignedAnalyst: req.user ? req.user.username : 'SOC Analyst',
      description,
      impact: impact || 'Potential security risk flagged during analysis.',
      evidence: evidence || [],
      timeline: [
        { action: 'Incident Created', detail: 'Reported to SOC Incident Response queue', user: req.user ? req.user.username : 'System', timestamp: now }
      ],
      detectionTime: now,
      lastUpdated: now
    });

    // Broadcast SSE
    try {
      const evRouter = require('../routes/events');
      if (evRouter.broadcast) {
        evRouter.broadcast({
          type: 'incident_created',
          incidentId: incident.incidentId,
          title: incident.title,
          severity: incident.severity,
          timestamp: now
        });
      }
    } catch (e) {}

    res.status(201).json({
      success: true,
      data: incident
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
};

// @desc    Update Incident Status
// @route   PATCH /api/incidents/:id/status
exports.updateIncidentStatus = async (req, res) => {
  try {
    const { id } = req.params;
    const { status, note } = req.body;

    const validStatuses = ['New', 'Investigating', 'Contained', 'Resolved', 'Closed'];
    if (!validStatuses.includes(status)) {
      return res.status(400).json({ success: false, error: 'Invalid status transition.' });
    }

    const incident = await Incident.findOne({ $or: [{ _id: id.match(/^[0-9a-fA-F]{24}$/) ? id : null }, { incidentId: id }].filter(Boolean) });
    if (!incident) {
      return res.status(404).json({ success: false, error: 'Incident not found.' });
    }

    const prevStatus = incident.status;
    incident.status = status;
    incident.lastUpdated = new Date();

    const username = req.user ? req.user.username : 'Analyst';
    incident.timeline.unshift({
      action: `Status Changed: ${prevStatus} ➔ ${status}`,
      detail: note || `Incident status updated to ${status}`,
      user: username,
      timestamp: new Date()
    });

    if (note) {
      incident.investigationNotes.unshift({
        author: username,
        note: `[Status Change to ${status}] ${note}`,
        timestamp: new Date()
      });
    }

    await incident.save();

    // Audit Log
    try {
      await Log.create({
        username,
        action: 'INCIDENT_STATUS_CHANGE',
        details: `Incident ${incident.incidentId} changed from ${prevStatus} to ${status}`,
        status: 'SUCCESS'
      });
    } catch (e) {}

    res.status(200).json({
      success: true,
      data: incident
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
};

// @desc    Add Analyst Note
// @route   POST /api/incidents/:id/notes
exports.addInvestigationNote = async (req, res) => {
  try {
    const { id } = req.params;
    const { note } = req.body;

    if (!note || typeof note !== 'string' || note.trim() === '') {
      return res.status(400).json({ success: false, error: 'Note content is required.' });
    }

    const incident = await Incident.findOne({ $or: [{ _id: id.match(/^[0-9a-fA-F]{24}$/) ? id : null }, { incidentId: id }].filter(Boolean) });
    if (!incident) {
      return res.status(404).json({ success: false, error: 'Incident not found.' });
    }

    const username = req.user ? req.user.username : 'Security Analyst';
    const now = new Date();

    incident.investigationNotes.unshift({
      author: username,
      note: note.trim(),
      timestamp: now
    });

    incident.timeline.unshift({
      action: 'Analyst Note Added',
      detail: note.trim().substring(0, 80) + (note.trim().length > 80 ? '...' : ''),
      user: username,
      timestamp: now
    });

    incident.lastUpdated = now;
    await incident.save();

    res.status(200).json({
      success: true,
      data: incident
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
};

// @desc    Generate AI Incident Analysis & Response Plan
// @route   POST /api/incidents/:id/ai-analyze
exports.aiAnalyzeIncident = async (req, res) => {
  try {
    const { id } = req.params;
    const incident = await Incident.findOne({ $or: [{ _id: id.match(/^[0-9a-fA-F]{24}$/) ? id : null }, { incidentId: id }].filter(Boolean) });
    if (!incident) {
      return res.status(404).json({ success: false, error: 'Incident not found.' });
    }

    const prompt = `Analyze this security incident and produce:
1. Root-cause hypothesis
2. Technical impact assessment
3. Actionable containment and remediation plan

Incident Details:
- Title: ${incident.title}
- Severity: ${incident.severity}
- Asset: ${incident.relatedAsset}
- Vulnerability: ${incident.relatedVulnerability || 'N/A'}
- Threat: ${incident.relatedThreat || 'N/A'}
- Description: ${incident.description}
- Evidence: ${JSON.stringify(incident.evidence || [])}`;

    const aiResponse = await callGeminiAPI(prompt, { incident }, 'investigation');

    incident.aiAnalysis = aiResponse;
    incident.lastUpdated = new Date();
    await incident.save();

    res.status(200).json({
      success: true,
      data: {
        incidentId: incident.incidentId,
        aiAnalysis: aiResponse
      }
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
};
