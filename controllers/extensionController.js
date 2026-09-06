/**
 * CyberShield – Chrome Extension API Controller
 * Lightweight domain threat check, alert saving, and false-positive reporting.
 * Privacy: accepts domain name ONLY – never full URL paths or query strings.
 */

const axios = require('axios');
const { checkSsrfHostname } = require('../utils/securityScanner');
const { predictUrlPhishing } = require('../utils/aiClient');
const Scan = require('../models/Scan');
const Log = require('../models/Log');
const Notification = require('../models/Notification');
const { URL } = require('url');

// ---------------------------------------------------------------------------
// Keep legacy extensionScan for backward-compat with old extension versions
// ---------------------------------------------------------------------------
exports.extensionScan = async (req, res) => {
  try {
    const { url } = req.body;
    if (!url) {
      return res.status(400).json({ success: false, error: 'URL required.' });
    }

    let hostname;
    try {
      hostname = new URL(url.startsWith('http') ? url : 'https://' + url).hostname;
    } catch (_) {
      return res.status(400).json({ success: false, error: 'Invalid URL format.' });
    }

    const ssrf = checkSsrfHostname(hostname);
    if (ssrf && ssrf.ssrfBlocked) {
      return res.status(403).json({ success: false, error: 'Private network resources are not permitted.' });
    }

    const result = await predictUrlPhishing(url);

    res.json({
      success: true,
      data: {
        url,
        domain:          hostname,
        status:          result.status,
        riskScore:       result.riskPercentage,
        confidence:      result.confidenceScore,
        isHttps:         url.startsWith('https://'),
        recommendations: result.recommendations || []
      }
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
};

// ---------------------------------------------------------------------------
// In-memory result cache (domain → { result, ts })
// TTL: 60 seconds for fast repeated checks
// ---------------------------------------------------------------------------
const _cache = new Map();
const CACHE_TTL_MS = 60 * 1000;

function getCached(domain) {
  const entry = _cache.get(domain);
  if (!entry) return null;
  if (Date.now() - entry.ts > CACHE_TTL_MS) { _cache.delete(domain); return null; }
  return entry.result;
}

function setCache(domain, result) {
  if (_cache.size > 5000) { const k = _cache.keys().next().value; _cache.delete(k); }
  _cache.set(domain, { result, ts: Date.now() });
}

// ---------------------------------------------------------------------------
// Google Safe Browsing API v4 lookup
// ---------------------------------------------------------------------------
async function checkSafeBrowsing(domain) {
  const key = process.env.GOOGLE_SAFE_BROWSING_KEY;
  if (!key) return null; // gracefully skip – heuristic will run

  const apiUrl = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${key}`;
  const body = {
    client: { clientId: 'cybershield-extension', clientVersion: '1.0.0' },
    threatInfo: {
      threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
      platformTypes: ['ANY_PLATFORM'],
      threatEntryTypes: ['URL'],
      threatEntries: [{ url: `https://${domain}/` }, { url: `http://${domain}/` }]
    }
  };

  try {
    const res = await axios.post(apiUrl, body, { timeout: 3000 });
    if (res.data && res.data.matches && res.data.matches.length > 0) {
      return { found: true, threatType: res.data.matches[0].threatType || 'UNKNOWN' };
    }
    return { found: false };
  } catch (_) {
    return null; // Safe Browsing unavailable — fall through to heuristic
  }
}

// ---------------------------------------------------------------------------
// @desc  POST /api/extension/check
// @body  { domain: "example.com", isHttps: true }
// @auth  None
// ---------------------------------------------------------------------------
exports.checkDomain = async (req, res) => {
  try {
    let { domain, isHttps } = req.body;

    if (!domain || typeof domain !== 'string') {
      return res.status(400).json({ success: false, error: 'domain is required.' });
    }

    domain = domain.trim().toLowerCase().replace(/^www\./, '');

    if (domain.length > 253 || domain.length < 3) {
      return res.status(400).json({ success: false, error: 'Invalid domain.' });
    }

    // SSRF Protection
    const ssrf = checkSsrfHostname(domain);
    if (ssrf && ssrf.ssrfBlocked) {
      return res.json({
        success: true,
        data: { outcome: 'NO_THREAT', reason: 'Local/private address — not checked.', source: 'ssrf-guard', domain, isHttps: !!isHttps, checkedAt: new Date().toISOString() }
      });
    }

    // Cache hit
    const cached = getCached(domain);
    if (cached) return res.json({ success: true, data: { ...cached, fromCache: true } });

    let result;
    const sbCheck = await checkSafeBrowsing(domain);

    if (sbCheck === null) {
      // Safe Browsing unreachable — use heuristic only
      const aiResult = await predictUrlPhishing(`https://${domain}/`);
      let outcome = 'NO_THREAT';
      if (aiResult.riskPercentage >= 65) outcome = 'KNOWN_THREAT';
      else if (aiResult.riskPercentage >= 35) outcome = 'SUSPICIOUS';

      result = {
        outcome,
        reason: outcome === 'NO_THREAT' ? 'No suspicious signals detected.' : (aiResult.recommendations[0] || 'Suspicious URL patterns detected.'),
        source: 'CyberShield Heuristic Engine',
        riskScore: aiResult.riskPercentage,
        domain, isHttps: !!isHttps, checkedAt: new Date().toISOString()
      };
    } else if (sbCheck.found) {
      const threatLabel = sbCheck.threatType === 'SOCIAL_ENGINEERING' ? 'Phishing/Social Engineering'
        : sbCheck.threatType === 'MALWARE' ? 'Malware Distribution'
          : sbCheck.threatType.replace(/_/g, ' ').toLowerCase();

      result = {
        outcome: 'KNOWN_THREAT',
        reason: `Listed as ${threatLabel} by Google Safe Browsing.`,
        source: 'Google Safe Browsing',
        domain, isHttps: !!isHttps, checkedAt: new Date().toISOString()
      };
    } else {
      const aiResult = await predictUrlPhishing(`https://${domain}/`);
      let outcome = 'NO_THREAT';
      let reason = 'No known threats detected.';

      if (aiResult.riskPercentage >= 35) {
        outcome = 'SUSPICIOUS';
        reason = aiResult.recommendations[0] || 'Suspicious URL pattern detected.';
      }

      result = {
        outcome, reason,
        source: process.env.GOOGLE_SAFE_BROWSING_KEY ? 'Google Safe Browsing + CyberShield Heuristic' : 'CyberShield Heuristic Engine',
        riskScore: aiResult.riskPercentage,
        domain, isHttps: !!isHttps, checkedAt: new Date().toISOString()
      };
    }

    setCache(domain, result);
    return res.json({ success: true, data: result });

  } catch (err) {
    console.error('[Extension Check Error]', err.message);
    return res.json({
      success: true,
      data: { outcome: 'CHECK_FAILED', reason: 'Unable to complete security check.', source: 'CyberShield', domain: req.body.domain || 'unknown', isHttps: false, checkedAt: new Date().toISOString() }
    });
  }
};

// ---------------------------------------------------------------------------
// @desc  POST /api/extension/alert
// @body  { domain, outcome, reason, source }
// @auth  Required
// ---------------------------------------------------------------------------
exports.saveAlert = async (req, res) => {
  try {
    const { domain, outcome, reason, source } = req.body;
    if (!domain || !outcome) return res.status(400).json({ success: false, error: 'domain and outcome are required.' });

    const severityMap = { KNOWN_THREAT: 'CRITICAL', SUSPICIOUS: 'HIGH', NO_THREAT: 'LOW', CHECK_FAILED: 'INFO' };
    const typeMap = { KNOWN_THREAT: 'critical', SUSPICIOUS: 'warning', NO_THREAT: 'info', CHECK_FAILED: 'info' };

    const notification = await Notification.create({
      user: req.user._id,
      title: `Extension Alert: ${outcome.replace(/_/g, ' ')} — ${domain}`,
      message: reason || `CyberShield Extension detected a threat on ${domain}`,
      type: typeMap[outcome] || 'warning',
      category: 'security',
      severity: severityMap[outcome] || 'HIGH',
      asset: domain,
      source: source || 'CyberShield Extension',
      recommendedAction: outcome === 'KNOWN_THREAT'
        ? 'Do not visit this site. Report it if you believe this is an error.'
        : 'Proceed with caution and verify the site identity.',
      actionUrl: `scanner.html?url=https://${domain}`,
      actionLabel: 'Run Full Scan'
    });

    try {
      await Scan.create({
        user: req.user._id,
        scanType: 'browser_reputation',
        target: domain,
        status: outcome === 'KNOWN_THREAT' ? 'Phishing' : outcome === 'SUSPICIOUS' ? 'Suspicious' : 'Safe',
        riskScore: outcome === 'KNOWN_THREAT' ? 95 : outcome === 'SUSPICIOUS' ? 55 : 5,
        details: { outcome, source, savedFromExtension: true }
      });
    } catch (_) {}

    return res.json({ success: true, data: { notificationId: notification._id } });
  } catch (err) {
    console.error('[Extension Alert Error]', err.message);
    return res.status(500).json({ success: false, error: 'Failed to save alert.' });
  }
};

// ---------------------------------------------------------------------------
// @desc  POST /api/extension/report-false-positive
// @body  { domain, outcome }
// @auth  None
// ---------------------------------------------------------------------------
exports.reportFalsePositive = async (req, res) => {
  try {
    const { domain, outcome } = req.body;
    if (!domain) return res.status(400).json({ success: false, error: 'domain is required.' });

    await Log.create({
      username: req.user ? req.user.username : 'Extension User',
      action: 'FALSE_POSITIVE_REPORT',
      details: `Extension false positive: ${domain} | Was flagged as: ${outcome}`,
      status: 'WARNING'
    });

    _cache.delete(domain.toLowerCase().replace(/^www\./, ''));

    return res.json({ success: true, message: 'Thank you. Your report has been recorded.' });
  } catch (err) {
    console.error('[Extension Report Error]', err.message);
    return res.status(500).json({ success: false, error: 'Failed to record report.' });
  }
};
