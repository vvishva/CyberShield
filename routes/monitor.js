const express = require('express');
const router = express.Router();
const { protect } = require('../middleware/authMiddleware');
const Scan = require('../models/Scan');

const MONITOR_INTERVALS = {
  '1h': 60 * 60 * 1000,
  '6h': 6 * 60 * 60 * 1000,
  '24h': 24 * 60 * 60 * 1000,
  '7d': 7 * 24 * 60 * 60 * 1000
};

// Get monitored domains for current user
router.get('/', protect, async (req, res) => {
  try {
    const scans = await Scan.find({ 
      user: req.user._id,
      scanType: { $in: ['website_security', 'url_phishing'] }
    })
    .select('target scanType status riskScore createdAt details')
    .sort({ createdAt: -1 })
    .limit(50);

    // Group by target to get latest status per domain
    const domainMap = new Map();
    scans.forEach(scan => {
      if (!domainMap.has(scan.target) || new Date(scan.createdAt) > new Date(domainMap.get(scan.target).createdAt)) {
        domainMap.set(scan.target, scan);
      }
    });

    const monitored = Array.from(domainMap.values()).map(scan => ({
      target: scan.target,
      scanType: scan.scanType,
      status: scan.status,
      riskScore: scan.riskScore,
      lastScanned: scan.createdAt,
      details: scan.details
    }));

    res.status(200).json({
      success: true,
      count: monitored.length,
      data: monitored
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Add domain to monitoring
router.post('/', protect, async (req, res) => {
  try {
    const { target, interval = '24h' } = req.body;
    
    if (!target) {
      return res.status(400).json({ success: false, error: 'Target URL is required' });
    }

    // For now, just return success - actual scheduling would be implemented in a job queue
    res.status(201).json({
      success: true,
      message: `Monitoring scheduled for ${target} every ${interval}`,
      data: { target, interval, nextRun: new Date(Date.now() + MONITOR_INTERVALS[interval]) }
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Remove domain from monitoring
router.delete('/:target', protect, async (req, res) => {
  try {
    const { target } = req.params;
    res.status(200).json({
      success: true,
      message: `Monitoring removed for ${target}`
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

module.exports = router;