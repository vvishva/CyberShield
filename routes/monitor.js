const express = require('express');
const router = express.Router();
const { protect } = require('../middleware/authMiddleware');
const { scanWebsiteSecurity } = require('../utils/securityScanner');

// In-memory monitor store (per-process; for production use MongoDB)
const monitors = new Map();

// GET /api/monitor — list user's monitored domains
router.get('/', protect, (req, res) => {
  const userId = String(req.user._id);
  const userMonitors = [];
  monitors.forEach((m, id) => {
    if (m.userId === userId) userMonitors.push({ _id: id, ...m });
  });
  res.json({ success: true, data: userMonitors });
});

// POST /api/monitor — add domain
router.post('/', protect, async (req, res) => {
  try {
    const { domain, interval } = req.body;
    if (!domain) return res.status(400).json({ success: false, error: 'Domain is required' });

    const id = 'mon_' + Date.now();
    const userId = String(req.user._id);
    const intervalMs = (parseInt(interval) || 30) * 60 * 1000;
    const entry = {
      userId,
      domain: domain.replace(/^https?:\/\//, '').replace(/\/+$/, ''),
      interval: parseInt(interval) || 30,
      active: true,
      lastScore: null,
      lastScan: null,
      nextScan: new Date(Date.now() + intervalMs).toISOString()
    };
    monitors.set(id, entry);

    // Run first scan immediately in background
    runMonitorScan(id, entry);

    res.status(201).json({ success: true, data: { _id: id, ...entry } });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// PATCH /api/monitor/:id/toggle — pause/resume
router.patch('/:id/toggle', protect, (req, res) => {
  const m = monitors.get(req.params.id);
  if (!m) return res.status(404).json({ success: false, error: 'Monitor not found' });
  m.active = !m.active;
  if (m.active) m.nextScan = new Date(Date.now() + m.interval * 60000).toISOString();
  res.json({ success: true, data: { _id: req.params.id, ...m } });
});

// DELETE /api/monitor/:id — remove
router.delete('/:id', protect, (req, res) => {
  monitors.delete(req.params.id);
  res.json({ success: true, message: 'Monitor removed' });
});

// Background scan runner
async function runMonitorScan(id, entry) {
  try {
    const result = await scanWebsiteSecurity(entry.domain);
    if (monitors.has(id)) {
      const m = monitors.get(id);
      m.lastScore = result.securityScore || 0;
      m.lastScan = new Date().toISOString();
      m.nextScan = m.active ? new Date(Date.now() + m.interval * 60000).toISOString() : null;
    }
  } catch (e) {
    console.warn('[Monitor] Scan failed for', entry.domain, e.message);
  }
}

// Background loop — runs every 60 seconds
setInterval(() => {
  const now = Date.now();
  monitors.forEach((m, id) => {
    if (m.active && m.nextScan && new Date(m.nextScan).getTime() <= now) {
      runMonitorScan(id, m);
    }
  });
}, 60 * 1000);

module.exports = router;