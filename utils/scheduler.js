const MonitoredSite = require('../models/MonitoredSite');
const Scan = require('../models/Scan');
const { scanWebsiteSecurity } = require('./securityScanner');
const { predictUrlPhishing } = require('./aiClient');

// ---------------------------------------------------------------------------
// SSE events router reference (injected by server.js via startScheduler)
// ---------------------------------------------------------------------------
let eventsRouter = null;
function setEventsRouter(router) { eventsRouter = router; }

// ---------------------------------------------------------------------------
// runMonitoringCycle — processes up to 5 due sites per invocation to avoid
// saturating the event loop or hitting external rate limits.
// ---------------------------------------------------------------------------
async function runMonitoringCycle() {
  try {
    const now = new Date();
    const dueSites = await MonitoredSite.find(
      { active: true, nextScan: { $lte: now } }
    ).limit(5);

    for (const site of dueSites) {
      try {
        const url = 'https://' + site.domain;
        const result = await scanWebsiteSecurity(url);

        // Skip sites blocked by SSRF guard (private/loopback addresses)
        if (result.ssrfBlocked) continue;

        const scan = await Scan.create({
          user:            site.user,
          scanType:        'website_security',
          target:          url,
          status:          result.riskLevel || 'Unknown',
          riskScore:       100 - (result.securityScore || 50),
          details:         result,
          recommendations: result.recommendations || []
        });

        // Persist updated stats on the MonitoredSite document
        const prevScore = site.lastScore;
        site.lastScan   = now;
        site.nextScan   = new Date(now.getTime() + site.interval * 60 * 1000);
        site.lastScore  = result.securityScore;
        site.lastStatus = result.riskLevel;
        site.lastScanId = scan._id;
        site.scoreHistory.push({ score: result.securityScore, date: now });
        // Cap history to the last 30 data points
        if (site.scoreHistory.length > 30) {
          site.scoreHistory = site.scoreHistory.slice(-30);
        }
        await site.save();

        // Broadcast live update to all connected dashboard clients
        if (eventsRouter && eventsRouter.broadcast) {
          eventsRouter.broadcast({
            type:         'scan_complete',
            domain:       site.domain,
            score:        result.securityScore,
            status:       result.riskLevel,
            scoreChanged: prevScore !== null && Math.abs(prevScore - result.securityScore) >= 5,
            prevScore,
            timestamp:    now
          });
        }
      } catch (err) {
        console.error('[Scheduler] Error scanning', site.domain, '—', err.message);
      }
    }
  } catch (err) {
    console.error('[Scheduler] Cycle error:', err.message);
  }
}

// ---------------------------------------------------------------------------
// startScheduler — call once at server startup.
// Runs a monitoring cycle every 5 minutes in the background.
// ---------------------------------------------------------------------------
function startScheduler(router) {
  eventsRouter = router;
  setInterval(runMonitoringCycle, 5 * 60 * 1000);
  console.log('[CyberShield Scheduler] Background monitoring active (5-min cycle)');
}

module.exports = { startScheduler, setEventsRouter, runMonitoringCycle };
