/**
 * CyberShield — Network Risk Detection Middleware
 *
 * Passively evaluates request network context on sensitive routes,
 * tracks admin/sensitive endpoint access, and attaches telemetry
 * without slowing down normal user experience.
 */

const { evaluateSession } = require('../services/networkRiskService');
const { extractClientIp } = require('../services/anonymousNetworkService');

/**
 * Sensitive endpoints list requiring behavioral flagging
 */
const SENSITIVE_PATTERNS = [
  /^\/api\/admin/i,
  /^\/api\/auth\/reset-password/i,
  /^\/api\/auth\/change-password/i,
  /^\/api\/user\/delete/i,
  /^\/api\/user\/security/i
];

function isSensitiveEndpoint(path) {
  if (!path) return false;
  return SENSITIVE_PATTERNS.some(regex => regex.test(path));
}

function isAdminEndpoint(path) {
  if (!path) return false;
  return /^\/api\/admin/i.test(path);
}

/**
 * Express middleware to track network risk on sensitive routes.
 * Runs asynchronously and never blocks or crashes the main request flow.
 */
function networkRiskMiddleware(req, res, next) {
  const path = req.originalUrl || req.path || '';
  const sensitive = isSensitiveEndpoint(path);
  const admin = isAdminEndpoint(path);

  // If endpoint is sensitive or admin, initiate an asynchronous evaluation
  if (sensitive || admin) {
    const clientIp = extractClientIp(req);
    // Non-blocking background evaluation
    setImmediate(async () => {
      try {
        await evaluateSession({
          req,
          user: req.user || null,
          ip: clientIp,
          sensitiveEndpoint: sensitive && !admin,
          adminEndpoint: admin
        });
      } catch (err) {
        // Defensive: never bubble to crash express pipeline
      }
    });
  }

  next();
}

module.exports = {
  networkRiskMiddleware,
  isSensitiveEndpoint,
  isAdminEndpoint
};
