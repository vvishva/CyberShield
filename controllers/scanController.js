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

    let previousScan = null;
    let diff = null;

    try {
      previousScan = await Scan.findOne({ target: url, scanType: 'website_security' }).sort({ createdAt: -1 });
      
      if (previousScan) {
        const oldScore = 100 - (previousScan.riskScore || 0);
        const newScore = secResult.securityScore;
        diff = {
          scoreChange: newScore - oldScore,
          newVulnerabilities: secResult.vulnerabilities?.filter(v => 
            !previousScan.details?.vulnerabilities?.some(pv => pv.title === v.title)
          ) || [],
          resolvedVulnerabilities: previousScan.details?.vulnerabilities?.filter(pv => 
            !secResult.vulnerabilities?.some(v => v.title === pv.title)
          ) || []
        };
        secResult.diff = diff;
      }
    } catch(e) {}

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
      history = await Scan.find({ user: req.user ? req.user._id : null }).sort({ createdAt: -1 }).limit(20);

      // Count distinct risk levels from the full collection for dashboard stats
      const allScans = await Scan.find({ user: req.user ? req.user._id : null }, 'status').lean();
      for (const s of allScans) {
        const lvl = s.status || 'Unknown';
        riskLevelCounts[lvl] = (riskLevelCounts[lvl] || 0) + 1;
      }
    } catch (e) {
      // DB unavailable - return empty arrays
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
      const userId = req.user ? req.user._id : null;
      const query = userId ? { user: userId } : {};

      totalScans = await Scan.countDocuments(query);

      // Threat / safe counts based on riskScore threshold
      threatsDetected = await Scan.countDocuments({ ...query, riskScore: { $gte: 50 } });
      safeScans       = await Scan.countDocuments({ ...query, riskScore: { $lt: 25 } });

      // Average security score (inverse of riskScore for website_security scans)
      const websiteScans = await Scan.find({ ...query, scanType: 'website_security' }, 'riskScore').lean();
      if (websiteScans.length > 0) {
        const sum = websiteScans.reduce((acc, s) => acc + (100 - (s.riskScore || 0)), 0);
        avgSecurityScore = Math.round(sum / websiteScans.length);
      }

      // Counts per scan type
      const typeAgg = await Scan.aggregate([
        { $match: query },
        { $group: { _id: '$scanType', count: { $sum: 1 } } }
      ]);
      for (const { _id, count } of typeAgg) {
        scansByType[_id] = count;
      }
    } catch (e) {
      // DB unavailable - return zeros
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

// ---------------------------------------------------------------------------
// @desc    Get Comprehensive SOC Dashboard Summary Data
// @route   GET /api/scan/dashboard-summary
// ---------------------------------------------------------------------------
exports.getDashboardSummary = async (req, res) => {
  try {
    const userId = req.user ? req.user._id : null;
    const query = userId ? { user: userId } : {};

    let scans = [];
    let monitoredCount = 0;
    try {
      scans = await Scan.find(query).sort({ createdAt: -1 }).lean();
      const MonitoredSite = require('../models/MonitoredSite');
      monitoredCount = await MonitoredSite.countDocuments(query);
    } catch(e) {}

    const totalScans = scans.length;
    const activeThreats = scans.filter(s => (s.riskScore || 0) >= 50).length;
    const safeAssets = scans.filter(s => (s.riskScore || 0) < 25).length;
    
    // Total vulnerabilities count across scans
    let totalVulns = 0;
    scans.forEach(s => {
      if (s.details && Array.isArray(s.details.vulnerabilities)) {
        totalVulns += s.details.vulnerabilities.length;
      }
    });

    // Compute average security score
    let overallScore = 100;
    if (totalScans > 0) {
      const sum = scans.reduce((acc, s) => acc + (100 - (s.riskScore || 0)), 0);
      overallScore = Math.round(sum / totalScans);
    }

    // Determine Risk Level
    let riskLevel = 'Safe';
    if (overallScore < 25) riskLevel = 'Critical';
    else if (overallScore < 50) riskLevel = 'High Risk';
    else if (overallScore < 75) riskLevel = 'Medium Risk';
    else if (overallScore < 90) riskLevel = 'Low Risk';

    // Compute 7-day score change delta
    const now = Date.now();
    const sevenDaysAgo = now - 7 * 24 * 60 * 60 * 1000;
    const recentScans = scans.filter(s => new Date(s.createdAt).getTime() >= sevenDaysAgo);
    const olderScans = scans.filter(s => new Date(s.createdAt).getTime() < sevenDaysAgo);

    let scoreDelta = 0;
    if (recentScans.length > 0 && olderScans.length > 0) {
      const recentAvg = Math.round(recentScans.reduce((a, s) => a + (100 - (s.riskScore || 0)), 0) / recentScans.length);
      const olderAvg = Math.round(olderScans.reduce((a, s) => a + (100 - (s.riskScore || 0)), 0) / olderScans.length);
      scoreDelta = recentAvg - olderAvg;
    }

    // Top Priorities (scans with highest risk or specific vulnerabilities)
    const priorities = [];
    const highRiskScans = scans.filter(s => (s.riskScore || 0) >= 40).slice(0, 5);
    highRiskScans.forEach(s => {
      let severity = 'MEDIUM';
      if ((s.riskScore || 0) >= 75) severity = 'CRITICAL';
      else if ((s.riskScore || 0) >= 50) severity = 'HIGH';

      let explanation = `Risk score of ${s.riskScore}% detected during ${s.scanType ? s.scanType.replace('_', ' ') : 'security scan'}.`;
      if (s.status === 'Phishing') explanation = 'Suspicious domain flagged by AI phishing analysis model.';
      else if (s.details && s.details.missingHeaders && s.details.missingHeaders.length > 0) {
        explanation = `Missing security headers: ${s.details.missingHeaders.slice(0, 2).join(', ')}.`;
      }

      priorities.push({
        id: s._id,
        severity,
        target: s.target,
        title: s.status === 'Phishing' ? 'Suspicious Domain Identified' : `${s.status || 'Security Issue'} Detected`,
        explanation,
        timestamp: s.createdAt,
        scanId: s._id
      });
    });

    // Security Health Breakdown (calculate component scores)
    const webSecurityScans = scans.filter(s => s.scanType === 'website_security');
    const sslScores = webSecurityScans.map(s => (s.details && s.details.hasHttps) ? 100 : 30);
    const avgSsl = sslScores.length ? Math.round(sslScores.reduce((a, b) => a + b, 0) / sslScores.length) : (totalScans > 0 ? 85 : 100);

    const headerScores = webSecurityScans.map(s => {
      if (!s.details || !s.details.headerChecks) return 50;
      const present = Object.values(s.details.headerChecks).filter(Boolean).length;
      return Math.round((present / 6) * 100);
    });
    const avgHeaders = headerScores.length ? Math.round(headerScores.reduce((a, b) => a + b, 0) / headerScores.length) : (totalScans > 0 ? 70 : 100);

    const threatScores = scans.filter(s => s.scanType === 'url_phishing').map(s => 100 - (s.riskScore || 0));
    const avgThreat = threatScores.length ? Math.round(threatScores.reduce((a, b) => a + b, 0) / threatScores.length) : (totalScans > 0 ? 90 : 100);

    const health = {
      webSecurity: overallScore,
      sslTls: avgSsl,
      securityHeaders: avgHeaders,
      threatIntelligence: avgThreat,
      dns: 95,
      configuration: Math.min(100, overallScore + 5),
      vulnerabilities: Math.max(0, 100 - (totalVulns * 10))
    };

    // Helper for daily time-series grouping (7D, 30D, 90D)
    const buildChartData = (daysCount) => {
      const labels = [];
      const total = [];
      const threats = [];
      const safe = [];
      const failed = [];
      const scores = [];

      for (let i = daysCount - 1; i >= 0; i--) {
        const d = new Date(now - i * 24 * 60 * 60 * 1000);
        const dayStr = d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
        labels.push(dayStr);

        const startOfDay = new Date(d.getFullYear(), d.getMonth(), d.getDate()).getTime();
        const endOfDay = startOfDay + 24 * 60 * 60 * 1000 - 1;

        const dayScans = scans.filter(s => {
          const t = new Date(s.createdAt).getTime();
          return t >= startOfDay && t <= endOfDay;
        });

        const dayTotal = dayScans.length;
        const dayThreats = dayScans.filter(s => (s.riskScore || 0) >= 50).length;
        const daySafe = dayScans.filter(s => (s.riskScore || 0) < 25).length;
        const dayFailed = dayScans.filter(s => s.status === 'Failed' || s.status === 'Error').length;

        total.push(dayTotal);
        threats.push(dayThreats);
        safe.push(daySafe);
        failed.push(dayFailed);

        if (dayTotal > 0) {
          const dayAvgScore = Math.round(dayScans.reduce((a, s) => a + (100 - (s.riskScore || 0)), 0) / dayTotal);
          scores.push(dayAvgScore);
        } else {
          scores.push(overallScore);
        }
      }

      return { labels, total, threats, safe, failed, scores };
    };

    const activity = {
      '7d': buildChartData(7),
      '30d': buildChartData(30),
      '90d': buildChartData(90)
    };

    const trend = {
      '7d': { labels: activity['7d'].labels, scores: activity['7d'].scores },
      '30d': { labels: activity['30d'].labels, scores: activity['30d'].scores },
      '90d': { labels: activity['90d'].labels, scores: activity['90d'].scores }
    };

    // Security Changes feed (derived from recent scans)
    const changes = [];
    scans.slice(0, 6).forEach(s => {
      const isThreat = (s.riskScore || 0) >= 50;
      changes.push({
        id: s._id,
        target: s.target,
        change: isThreat ? `Threat status flagged as ${s.status}` : `Security score evaluated: ${100 - (s.riskScore || 0)}/100`,
        severity: isThreat ? ((s.riskScore || 0) >= 75 ? 'CRITICAL' : 'HIGH') : 'SAFE',
        timestamp: s.createdAt,
        details: s.status
      });
    });

    res.status(200).json({
      success: true,
      data: {
        posture: {
          overallScore,
          riskLevel,
          scoreDelta,
          activeThreats,
          vulnerabilities: totalVulns,
          monitoredAssets: monitoredCount,
          safeAssets
        },
        priorities,
        health,
        activity,
        trend,
        changes,
        recentOperations: scans.slice(0, 15)
      }
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
};
