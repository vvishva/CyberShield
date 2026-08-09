const MonitoredSite = require('../models/MonitoredSite');

// ---------------------------------------------------------------------------
// @desc   Get all monitored sites for the authenticated user
// @route  GET /api/monitor
// ---------------------------------------------------------------------------
exports.getSites = async (req, res) => {
  try {
    const sites = await MonitoredSite.find({ user: req.user._id }).sort({ createdAt: -1 });
    res.json({ success: true, count: sites.length, data: sites });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
};

// ---------------------------------------------------------------------------
// @desc   Add a new site to monitoring
// @route  POST /api/monitor
// ---------------------------------------------------------------------------
exports.addSite = async (req, res) => {
  try {
    let { domain, displayName, interval } = req.body;

    if (!domain) {
      return res.status(400).json({ success: false, error: 'Domain is required.' });
    }

    // Strip protocol/path — store bare hostname only
    try {
      const url = domain.startsWith('http') ? domain : 'https://' + domain;
      domain = new (require('url').URL)(url).hostname.toLowerCase();
    } catch (_) {
      return res.status(400).json({ success: false, error: 'Invalid domain format.' });
    }

    // Prevent duplicate monitoring entries per user
    const existing = await MonitoredSite.findOne({ user: req.user._id, domain });
    if (existing) {
      return res.status(409).json({ success: false, error: `${domain} is already being monitored.` });
    }

    const site = await MonitoredSite.create({
      user: req.user._id,
      domain,
      displayName: displayName || domain,
      interval: interval || 30
    });

    res.status(201).json({ success: true, data: site });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
};

// ---------------------------------------------------------------------------
// @desc   Remove a monitored site by id (must belong to the requesting user)
// @route  DELETE /api/monitor/:id
// ---------------------------------------------------------------------------
exports.removeSite = async (req, res) => {
  try {
    const site = await MonitoredSite.findOne({ _id: req.params.id, user: req.user._id });
    if (!site) {
      return res.status(404).json({ success: false, error: 'Site not found or access denied.' });
    }
    await site.deleteOne();
    res.json({ success: true, data: {} });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
};

// ---------------------------------------------------------------------------
// @desc   Toggle active/paused status for a monitored site
// @route  PATCH /api/monitor/:id/toggle
// ---------------------------------------------------------------------------
exports.toggleSite = async (req, res) => {
  try {
    const site = await MonitoredSite.findOne({ _id: req.params.id, user: req.user._id });
    if (!site) {
      return res.status(404).json({ success: false, error: 'Site not found or access denied.' });
    }
    site.active = !site.active;
    // Reset nextScan when re-activating so it runs promptly
    if (site.active) {
      site.nextScan = new Date();
    }
    await site.save();
    res.json({ success: true, data: site });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
};
