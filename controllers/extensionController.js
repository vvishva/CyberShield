const { predictUrlPhishing } = require('../utils/aiClient');
const { checkSsrfHostname } = require('../utils/securityScanner');
const { URL } = require('url');

// ---------------------------------------------------------------------------
// @desc   Lightweight phishing-detection scan for the browser extension.
//         No auth required — designed for quick inline checks.
// @route  POST /api/scan/extension
// ---------------------------------------------------------------------------
exports.extensionScan = async (req, res) => {
  try {
    const { url } = req.body;
    if (!url) {
      return res.status(400).json({ success: false, error: 'URL required.' });
    }

    // Parse hostname for SSRF guard
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
