/**
 * CyberShield — Network Risk Scoring & Orchestration Engine
 *
 * Combines anonymous network indicators (VPN, Proxy, Tor, Hosting)
 * with behavioral and authentication indicators to calculate a weighted,
 * defensive risk score between 0 and 100.
 *
 * Implements deduplication, event cooldown, alerts generation, and SSE broadcasting.
 */

const NetworkRiskEvent = require('../models/NetworkRiskEvent');
const NetworkRiskConfig = require('../models/NetworkRiskConfig');
const Notification = require('../models/Notification');
const Log = require('../models/Log');
const { inspectIp, extractClientIp } = require('./anonymousNetworkService');

// Try to safely require SSE broadcaster if available
let broadcastSSE = null;
try {
  const eventsModule = require('../routes/events');
  if (eventsModule && typeof eventsModule.broadcast === 'function') {
    broadcastSSE = eventsModule.broadcast;
  }
} catch (_) {}

// Default configuration fallback
const DEFAULT_CONFIG = {
  enabled: true,
  weights: {
    vpn: 15,
    proxy: 15,
    tor: 25,
    hosting: 15,
    failedLogins: 20,
    newSession: 10,
    suspiciousApi: 20,
    sensitiveEndpoint: 15,
    rateLimitViolation: 15
  },
  thresholds: {
    lowMax: 30,
    mediumMax: 60,
    highMax: 80
  },
  alertThreshold: 'High',
  cooldownMinutes: 5
};

// In-memory failed login tracker: key (ip or ip:username) -> { count, lastAttempt }
const failedLoginTracker = new Map();

// Periodic prune of failed logins older than 15 minutes
const pruneTimer = setInterval(() => {
  const fifteenMinsAgo = Date.now() - 15 * 60 * 1000;
  for (const [key, record] of failedLoginTracker.entries()) {
    if (record.lastAttempt < fifteenMinsAgo) {
      failedLoginTracker.delete(key);
    }
  }
}, 5 * 60 * 1000);
if (pruneTimer.unref) pruneTimer.unref();

/**
 * Retrieves the active risk configuration from the database or returns default.
 */
async function getConfig() {
  try {
    const config = await NetworkRiskConfig.findOne({ configKey: 'default_config' }).lean();
    if (config) {
      return {
        ...DEFAULT_CONFIG,
        ...config,
        weights: { ...DEFAULT_CONFIG.weights, ...(config.weights || {}) },
        thresholds: { ...DEFAULT_CONFIG.thresholds, ...(config.thresholds || {}) }
      };
    }
  } catch (err) {
    // Database fallback
  }
  return DEFAULT_CONFIG;
}

/**
 * Tracks a failed authentication attempt for an IP and identifier.
 */
function recordFailedLogin(ip, username = '') {
  const cleanIp = (ip || '').trim() || '127.0.0.1';
  const key = `${cleanIp}:${username}`;
  const now = Date.now();

  const current = failedLoginTracker.get(key) || { count: 0, lastAttempt: now };
  current.count += 1;
  current.lastAttempt = now;
  failedLoginTracker.set(key, current);

  // Also track IP level aggregation
  const ipCurrent = failedLoginTracker.get(cleanIp) || { count: 0, lastAttempt: now };
  ipCurrent.count += 1;
  ipCurrent.lastAttempt = now;
  failedLoginTracker.set(cleanIp, ipCurrent);

  return current.count;
}

/**
 * Clears failed login counter on successful authentication.
 */
function clearFailedLogin(ip, username = '') {
  const cleanIp = (ip || '').trim() || '127.0.0.1';
  failedLoginTracker.delete(`${cleanIp}:${username}`);
  failedLoginTracker.delete(cleanIp);
}

/**
 * Gets the current failed login count for an IP or identifier.
 */
function getFailedLoginCount(ip, username = '') {
  const cleanIp = (ip || '').trim() || '127.0.0.1';
  const specific = failedLoginTracker.get(`${cleanIp}:${username}`);
  if (specific) return specific.count;
  const ipOnly = failedLoginTracker.get(cleanIp);
  return ipOnly ? ipOnly.count : 0;
}

/**
 * Core Evaluation Engine:
 * Analyzes network signals + behavioral indicators -> Calculates score -> Persists & Notifies.
 */
async function evaluateSession({
  req = null,
  user = null,
  ip = null,
  sessionId = null,
  failedLoginCount = null,
  isNewSession = false,
  sensitiveEndpoint = false,
  adminEndpoint = false,
  rateLimitViolation = false,
  suspiciousApi = false,
  contextNote = ''
}) {
  const config = await getConfig();
  if (config.enabled === false) return null;

  // 1. Resolve Client IP
  const clientIp = ip || (req ? extractClientIp(req) : '127.0.0.1');

  // 2. Perform Anonymous Network Inspection (Cached / Fast)
  const networkIntel = await inspectIp(clientIp);

  // 3. Resolve User Details
  const userId = user ? (user._id || user.id) : null;
  const username = user ? (user.username || user.email || 'Authenticated User') : 'Anonymous / Guest';

  // 4. Resolve Failed Login Count if not explicitly provided
  const failureCount = failedLoginCount !== null ? failedLoginCount : getFailedLoginCount(clientIp, username);

  // 5. Gather and Score Signals
  const signals = [];
  let rawScore = 0;
  const weights = config.weights;

  // Signal: Tor Exit Node (+25)
  if (networkIntel.torDetected) {
    const w = weights.tor;
    rawScore += w;
    signals.push({
      code: 'TOR_EXIT_NODE',
      name: 'Tor Exit Node Detected',
      weight: w,
      category: 'network',
      detail: 'Request routes through a verified Tor onion routing exit relay.'
    });
  }

  // Signal: VPN Detected (+15)
  if (networkIntel.vpnDetected && !networkIntel.torDetected) {
    const w = weights.vpn;
    rawScore += w;
    signals.push({
      code: 'VPN_DETECTED',
      name: 'Commercial VPN Tunnel',
      weight: w,
      category: 'network',
      detail: 'IP is identified with a commercial or anonymizing VPN tunnel.'
    });
  }

  // Signal: Proxy Detected (+15)
  if (networkIntel.proxyDetected && !networkIntel.torDetected) {
    const w = weights.proxy;
    rawScore += w;
    signals.push({
      code: 'PROXY_DETECTED',
      name: 'Forward/Web Proxy Gateway',
      weight: w,
      category: 'network',
      detail: 'Request originates from an intermediate proxy server.'
    });
  }

  // Signal: Hosting / Datacenter Infrastructure (+15)
  if (networkIntel.hostingDetected) {
    const w = weights.hosting;
    rawScore += w;
    signals.push({
      code: 'HOSTING_DATACENTER',
      name: 'Cloud / Datacenter Subnet',
      weight: w,
      category: 'network',
      detail: 'IP belongs to cloud infrastructure (AWS/Azure/GCP/DO) rather than residential broadband.'
    });
  }

  // Signal: Repeated Failed Login Attempts (+20)
  if (failureCount >= 2) {
    const w = weights.failedLogins;
    rawScore += w;
    signals.push({
      code: 'FAILED_LOGINS',
      name: 'Repeated Failed Authentication Attempts',
      weight: w,
      category: 'authentication',
      detail: `${failureCount} consecutive failed login attempts recorded in recent window.`
    });
  }

  // Signal: New / Unrecognized Session (+10)
  if (isNewSession) {
    const w = weights.newSession;
    rawScore += w;
    signals.push({
      code: 'NEW_SESSION',
      name: 'Unrecognized Device / Session',
      weight: w,
      category: 'behavioral',
      detail: 'Session originated from an unrecognized browser/device or network fingerprint.'
    });
  }

  // Signal: Sensitive Endpoint Access (+15)
  if (sensitiveEndpoint || adminEndpoint) {
    const w = adminEndpoint ? weights.adminEndpointAccess || 15 : weights.sensitiveEndpoint;
    rawScore += w;
    signals.push({
      code: adminEndpoint ? 'ADMIN_ENDPOINT_ACCESS' : 'SENSITIVE_ENDPOINT_ACCESS',
      name: adminEndpoint ? 'Privileged Admin Endpoint Access' : 'Sensitive Asset Access',
      weight: w,
      category: 'behavioral',
      detail: adminEndpoint
        ? 'Targeted administrative management API route.'
        : 'Targeted account security or credentials management API.'
    });
  }

  // Signal: Rate Limit Violation (+15)
  if (rateLimitViolation) {
    const w = weights.rateLimitViolation;
    rawScore += w;
    signals.push({
      code: 'RATE_LIMIT_VIOLATION',
      name: 'Rate-Limit Threshold Exceeded',
      weight: w,
      category: 'behavioral',
      detail: 'Request frequency breached automated application velocity thresholds.'
    });
  }

  // Signal: Suspicious API Activity (+20)
  if (suspiciousApi) {
    const w = weights.suspiciousApi;
    rawScore += w;
    signals.push({
      code: 'SUSPICIOUS_API_ACTIVITY',
      name: 'Anomalous Request Signature',
      weight: w,
      category: 'threat',
      detail: 'Unusual query structure, rapid probing, or malformed parameters detected.'
    });
  }

  // 6. Cap final score strictly between 0 and 100
  const finalScore = Math.max(0, Math.min(100, rawScore));

  // 7. Assign Risk Category
  const thresholds = config.thresholds;
  let riskLevel = 'Low';
  if (finalScore > thresholds.highMax) {
    riskLevel = 'Critical';
  } else if (finalScore > thresholds.mediumMax) {
    riskLevel = 'High';
  } else if (finalScore > thresholds.lowMax) {
    riskLevel = 'Medium';
  } else {
    riskLevel = 'Low';
  }

  // 8. Generate Clear, Non-Judgmental Explanation
  const explanation = generateExplanation({
    networkIntel,
    signals,
    finalScore,
    riskLevel,
    failureCount
  });

  // 9. Generate Recommended Defensive Response
  const recommendedAction = generateRecommendedAction(riskLevel, signals);

  // 10. Deduplication & Cooldown Check (5 minutes default)
  const cooldownMs = (config.cooldownMinutes || 5) * 60 * 1000;
  const cooldownCutoff = new Date(Date.now() - cooldownMs);

  const existingRecentEvent = await NetworkRiskEvent.findOne({
    ipAddress: clientIp,
    userId: userId || null,
    riskLevel,
    createdAt: { $gte: cooldownCutoff }
  }).sort({ createdAt: -1 });

  let savedEvent;

  if (existingRecentEvent) {
    // Update existing event instead of spamming duplicates
    existingRecentEvent.riskScore = finalScore;
    existingRecentEvent.signals = signals;
    existingRecentEvent.explanation = explanation;
    existingRecentEvent.failedLoginCount = failureCount;
    existingRecentEvent.updatedAt = new Date();
    savedEvent = await existingRecentEvent.save();
  } else {
    // Create new event
    savedEvent = await NetworkRiskEvent.create({
      userId,
      username,
      sessionId,
      ipAddress: clientIp,
      networkType: networkIntel.networkType,
      vpnDetected: networkIntel.vpnDetected,
      proxyDetected: networkIntel.proxyDetected,
      torDetected: networkIntel.torDetected,
      hostingDetected: networkIntel.hostingDetected,
      country: networkIntel.country,
      region: networkIntel.region,
      city: networkIntel.city,
      isp: networkIntel.isp,
      asn: networkIntel.asn,
      failedLoginCount: failureCount,
      suspiciousActivity: suspiciousApi || rateLimitViolation,
      signals,
      riskScore: finalScore,
      riskLevel,
      explanation,
      recommendedAction,
      userAgent: req ? (req.headers['user-agent'] || '') : '',
      endpoint: req ? (req.originalUrl || req.url || '') : ''
    });

    // 11. Security Alerts & Notifications for High / Critical Events
    const alertOrder = { Low: 1, Medium: 2, High: 3, Critical: 4 };
    const thresholdOrder = alertOrder[config.alertThreshold] || 3;

    if (alertOrder[riskLevel] >= thresholdOrder) {
      try {
        await Notification.create({
          user: userId,
          title: `Anonymous Network Alert: ${riskLevel} Risk Session Detected`,
          message: `${networkIntel.networkType} connection from ${clientIp} (${networkIntel.country}) scored ${finalScore}/100. ${explanation}`,
          type: riskLevel === 'Critical' ? 'critical' : 'warning',
          category: 'security',
          severity: riskLevel.toUpperCase(),
          asset: 'CyberShield Sentinel Network Guard',
          source: 'Anonymous Network Risk Detection Engine',
          recommendedAction,
          actionUrl: 'dashboard.html#anonymous-risk-section',
          actionLabel: 'Investigate Session'
        });
      } catch (_) {}
    }

    // 12. Real-Time SSE Broadcast to connected SOC dashboards
    if (broadcastSSE) {
      try {
        broadcastSSE({
          type: 'anonymous_network_risk',
          eventId: savedEvent._id,
          ip: clientIp,
          networkType: networkIntel.networkType,
          riskScore: finalScore,
          riskLevel,
          country: networkIntel.country,
          timestamp: savedEvent.createdAt
        });
      } catch (_) {}
    }
  }

  return savedEvent;
}

/**
 * Generates an objective, non-judgmental security explanation.
 */
function generateExplanation({ networkIntel, signals, finalScore, riskLevel, failureCount }) {
  const parts = [];

  if (networkIntel.torDetected) {
    parts.push('Session originates from a verified Tor exit relay');
  } else if (networkIntel.vpnDetected) {
    parts.push('Session routes through a commercial VPN tunnel');
  } else if (networkIntel.proxyDetected) {
    parts.push('Session connects via an intermediary proxy server');
  } else if (networkIntel.hostingDetected) {
    parts.push('Session originates from datacenter/cloud infrastructure');
  } else if (networkIntel.isPrivate) {
    return 'Internal loopback / RFC-1918 private address. Safe local infrastructure.';
  } else {
    parts.push('Session routes via standard residential or enterprise broadband');
  }

  if (failureCount >= 2) {
    parts.push(`with ${failureCount} consecutive authentication failures`);
  }

  const hasAdmin = signals.some(s => s.code === 'ADMIN_ENDPOINT_ACCESS');
  const hasSensitive = signals.some(s => s.code === 'SENSITIVE_ENDPOINT_ACCESS');
  const hasRate = signals.some(s => s.code === 'RATE_LIMIT_VIOLATION');
  const hasNew = signals.some(s => s.code === 'NEW_SESSION');

  if (hasAdmin) parts.push('and attempted access to privileged administrative interfaces');
  else if (hasSensitive) parts.push('and attempted access to sensitive credentials resources');

  if (hasRate) parts.push('under rapid request frequency breaching rate limits');
  if (hasNew) parts.push('from an unrecognized device fingerprint');

  let text = parts.join(' ');
  text = text.charAt(0).toUpperCase() + text.slice(1) + '.';
  return text;
}

/**
 * Generates actionable defensive SOC recommendations.
 */
function generateRecommendedAction(riskLevel, signals) {
  switch (riskLevel) {
    case 'Critical':
      return 'Immediate defensive triage recommended: inspect session tokens, verify user identity via out-of-band 2FA, and monitor for credential stuffing or administrative probing.';
    case 'High':
      return 'Heightened defensive monitoring: prompt for step-up multi-factor authentication if sensitive endpoints are requested, and review associated account logs.';
    case 'Medium':
      return 'Standard automated telemetry: log session context and monitor for subsequent anomalous behavioral spikes.';
    case 'Low':
    default:
      return 'Standard defensive monitoring: normal traffic profile with acceptable network characteristics. No analyst action required.';
  }
}

/**
 * Aggregates summary statistics for dashboard metric cards.
 */
async function getRiskSummary() {
  const [
    totalEvents,
    vpnSessions,
    proxySessions,
    torSessions,
    highRiskSessions,
    criticalAlerts
  ] = await Promise.all([
    NetworkRiskEvent.countDocuments(),
    NetworkRiskEvent.countDocuments({ vpnDetected: true }),
    NetworkRiskEvent.countDocuments({ proxyDetected: true }),
    NetworkRiskEvent.countDocuments({ torDetected: true }),
    NetworkRiskEvent.countDocuments({ riskLevel: 'High' }),
    NetworkRiskEvent.countDocuments({ riskLevel: 'Critical' })
  ]);

  const anonymousSessions = await NetworkRiskEvent.countDocuments({
    $or: [{ vpnDetected: true }, { proxyDetected: true }, { torDetected: true }, { hostingDetected: true }]
  });

  return {
    totalEvents,
    anonymousSessions,
    vpnSessions,
    proxySessions,
    torSessions,
    highRiskSessions,
    criticalAlerts
  };
}

module.exports = {
  evaluateSession,
  getConfig,
  recordFailedLogin,
  clearFailedLogin,
  getFailedLoginCount,
  getRiskSummary,
  _failedLoginTracker: failedLoginTracker
};
