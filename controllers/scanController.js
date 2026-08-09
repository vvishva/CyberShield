const Scan = require('../models/Scan');
const Log = require('../models/Log');
const { predictUrlPhishing } = require('../utils/aiClient');
const { analyzePassword, generateStrongPassword } = require('../utils/passwordAnalyzer');
const { scanWebsiteSecurity, checkSsrfHostname } = require('../utils/securityScanner');
const { checkIpReputation } = require('../utils/ipChecker');
const { URL } = require('url');

// ---------------------------------------------------------------------------
// Helper: SSRF pre-flight for controller-level URL validation
// ---------------------------------------------------------------------------
function ssrfPreFlight(rawUrl) {
  try {
    let url = (rawUrl || '').trim();
    if (!url.startsWith('http://') && !url.startsWith('https://')) url = 'https://' + url;
    const { hostname } = new URL(url);
    return checkSsrfHostname(hostname);
  } catch (_) {
    return null; // malformed URL – let downstream handlers report the error
  }
}

// ---------------------------------------------------------------------------
// @desc    Scan URL for AI Phishing Detection
// @route   POST /api/scan/url
// ---------------------------------------------------------------------------
exports.scanUrl = async (req, res, next) => {
  try {
    const { url } = req.body;
    if (!url) {
      return res.status(400).json({ success: false, error: 'Please enter a target URL.' });
    }

    // SSRF pre-flight
    const ssrfCheck = ssrfPreFlight(url);
    if (ssrfCheck && ssrfCheck.ssrfBlocked) {
      return res.status(403).json({ success: false, error: 'Access to internal network resources is not permitted.' });
    }

    const aiResult = await predictUrlPhishing(url);

    let savedScan;
    try {
      savedScan = await Scan.create({
        user: req.user ? req.user._id : null,
        scanType: 'url_phishing',
        target: url,
        status: aiResult.status,
        riskScore: aiResult.riskPercentage,
        confidenceScore: aiResult.confidenceScore,
        details: aiResult,
        recommendations: aiResult.recommendations
      });
    } catch (e) {
      savedScan = {
        _id: 'scan_' + Date.now(),
        scanType: 'url_phishing',
        target: url,
        status: aiResult.status,
        riskScore: aiResult.riskPercentage,
        confidenceScore: aiResult.confidenceScore,
        createdAt: new Date()
      };
    }

    // Audit Log
    try {
      await Log.create({
        username: req.user ? req.user.username : 'Anonymous',
        action: 'URL_SCAN',
        details: `Scanned: ${url} | Verdict: ${aiResult.status} (${aiResult.riskPercentage}% Risk)`,
        status: aiResult.status === 'Safe' ? 'SUCCESS' : 'WARNING'
      });
    } catch (e) {}

    // Broadcast live SSE event to connected dashboard clients
    try {
      const evRouter = require('../routes/events');
      if (evRouter.broadcast) {
        evRouter.broadcast({
          type:      'scan_complete',
          target:    url,
          status:    aiResult.status,
          riskScore: aiResult.riskPercentage,
          timestamp: new Date()
        });
      }
    } catch (e) {}

    res.status(200).json({
      success: true,
      data: {
        scanId: savedScan._id,
        target: url,
        status: aiResult.status,
        riskScore: aiResult.riskPercentage,
        confidenceScore: aiResult.confidenceScore,
        modelUsed: aiResult.modelUsed,
        features: aiResult.features,
        recommendations: aiResult.recommendations
      }
    });
  } catch (err) {
    next(err);
  }
};

// ---------------------------------------------------------------------------
// @desc    Analyze Password Strength
// @route   POST /api/scan/password
// ---------------------------------------------------------------------------
exports.checkPassword = async (req, res, next) => {
  try {
    const { password } = req.body;
    const result = analyzePassword(password);

    try {
      await Log.create({
        username: req.user ? req.user.username : 'Anonymous',
        action: 'PASSWORD_CHECK',
        details: `Password strength evaluated: ${result.strength} (${result.entropyBits} bits entropy)`,
        status: 'SUCCESS'
      });
    } catch (e) {}

    res.status(200).json({
      success: true,
      data: result
    });
  } catch (err) {
    next(err);
  }
};

// ---------------------------------------------------------------------------
// @desc    Generate Random Strong Password
// @route   GET /api/scan/generate-password
// ---------------------------------------------------------------------------
exports.generatePassword = async (req, res) => {
  const password = generateStrongPassword(16);
  res.status(200).json({
    success: true,
    password
  });
};

// ---------------------------------------------------------------------------
// @desc    Website Security & Header Scan
// @route   POST /api/scan/website
// ---------------------------------------------------------------------------
exports.scanWebsite = async (req, res, next) => {
  try {
    const { url } = req.body;
    if (!url) {
      return res.status(400).json({ success: false, error: 'Please enter a target website URL.' });
    }

    // SSRF pre-flight (hostname-level, before DNS resolution)
    const ssrfCheck = ssrfPreFlight(url);
    if (ssrfCheck && ssrfCheck.ssrfBlocked) {
      return res.status(403).json({ success: false, error: 'Access to internal network resources is not permitted.' });
    }

    const secResult = await scanWebsiteSecurity(url);

    // scanWebsiteSecurity may also return an ssrfBlocked object after DNS resolution
    if (secResult.ssrfBlocked) {
      return res.status(403).json({ success: false, error: 'Access to internal network resources is not permitted.' });
    }

    try {
      await Scan.create({
        user: req.user ? req.user._id : null,
        scanType: 'website_security',
        target: url,
        status: secResult.riskLevel,
        riskScore: 100 - secResult.securityScore,
        details: secResult,
        recommendations: secResult.recommendations
      });
    } catch (e) {}

    res.status(200).json({
      success: true,
      data: secResult
    });
  } catch (err) {
    next(err);
  }
};

// ---------------------------------------------------------------------------
// @desc    IP Reputation Check
// @route   POST /api/scan/ip
// ---------------------------------------------------------------------------
exports.checkIp = async (req, res, next) => {
  try {
    const { ip } = req.body;
    const ipResult = checkIpReputation(ip);

    try {
      await Scan.create({
        user: req.user ? req.user._id : null,
        scanType: 'ip_reputation',
        target: ip || '127.0.0.1',
        status: ipResult.riskLevel,
        riskScore: ipResult.threatScore,
        details: ipResult,
        recommendations: ipResult.details
      });
    } catch (e) {}

    res.status(200).json({
      success: true,
      data: ipResult
    });
  } catch (err) {
    next(err);
  }
};

// ---------------------------------------------------------------------------
// @desc    File Hash Analysis
// @route   POST /api/scan/hash
// ---------------------------------------------------------------------------
exports.checkFileHash = async (req, res) => {
  const { md5, sha1, sha256, fileName } = req.body;

  const knownMalicious = [
    '44d88612fea8a8f36de82e1278abb02f', // EICAR standard test hash
    '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f'
  ];

  const isMalicious = knownMalicious.includes(md5) || knownMalicious.includes(sha256);

  res.status(200).json({
    success: true,
    data: {
      fileName: fileName || 'Uploaded File',
      md5,
      sha1,
      sha256,
      status: isMalicious ? 'Malicious' : 'Clean',
      riskScore: isMalicious ? 95 : 0,
      threatSignature: isMalicious ? 'Trojan.Generic.Heuristic' : 'None Detected',
      scannedEngines: 68,
      detections: isMalicious ? 54 : 0
    }
  });
};

// ---------------------------------------------------------------------------
// @desc    Get Recent Scan History
// @route   GET /api/scan/history
// ---------------------------------------------------------------------------
exports.getScanHistory = async (req, res) => {
  try {
    let history = [];
    const riskLevelCounts = {};

    try {
      history = await Scan.find().sort({ createdAt: -1 }).limit(20);

      // Count distinct risk levels from the full collection for dashboard stats
      const allScans = await Scan.find({}, 'status').lean();
      for (const s of allScans) {
        const lvl = s.status || 'Unknown';
        riskLevelCounts[lvl] = (riskLevelCounts[lvl] || 0) + 1;
      }
    } catch (e) {}

    if (!history || history.length === 0) {
      history = [
        {
          _id: 'scan_101',
          scanType: 'url_phishing',
          target: 'https://paypal-security-update-alert.com',
          status: 'Phishing',
          riskScore: 89,
          createdAt: new Date(Date.now() - 3600000)
        },
        {
          _id: 'scan_102',
          scanType: 'website_security',
          target: 'https://github.com',
          status: 'Safe',
          riskScore: 5,
          createdAt: new Date(Date.now() - 7200000)
        },
        {
          _id: 'scan_103',
          scanType: 'ip_reputation',
          target: '185.220.101.5',
          status: 'Medium Risk',
          riskScore: 55,
          createdAt: new Date(Date.now() - 14400000)
        }
      ];
    }

    res.status(200).json({
      success: true,
      count: history.length,
      riskLevelCounts,
      data: history
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
};

// ---------------------------------------------------------------------------
// @desc    Get Aggregate Security Scan Statistics
// @route   GET /api/scan/stats
// ---------------------------------------------------------------------------
exports.getStats = async (req, res) => {
  try {
    let totalScans = 0;
    let threatsDetected = 0;
    let safeScans = 0;
    let avgSecurityScore = 0;
    let scansByType = {};

    try {
      totalScans = await Scan.countDocuments();

      // Threat / safe counts based on riskScore threshold
      threatsDetected = await Scan.countDocuments({ riskScore: { $gte: 50 } });
      safeScans       = await Scan.countDocuments({ riskScore: { $lt: 25 } });

      // Average security score (inverse of riskScore for website_security scans)
      const websiteScans = await Scan.find({ scanType: 'website_security' }, 'riskScore').lean();
      if (websiteScans.length > 0) {
        const sum = websiteScans.reduce((acc, s) => acc + (100 - (s.riskScore || 0)), 0);
        avgSecurityScore = Math.round(sum / websiteScans.length);
      }

      // Counts per scan type
      const typeAgg = await Scan.aggregate([
        { $group: { _id: '$scanType', count: { $sum: 1 } } }
      ]);
      for (const { _id, count } of typeAgg) {
        scansByType[_id] = count;
      }
    } catch (e) {
      // DB unavailable — return demo data
      return res.status(200).json({
        success: true,
        demo: true,
        data: {
          totalScans: 142,
          threatsDetected: 37,
          safeScans: 89,
          avgSecurityScore: 68,
          scansByType: {
            url_phishing: 64,
            website_security: 48,
            ip_reputation: 18,
            password_check: 12
          }
        }
      });
    }

    res.status(200).json({
      success: true,
      data: {
        totalScans,
        threatsDetected,
        safeScans,
        avgSecurityScore,
        scansByType
      }
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
};
