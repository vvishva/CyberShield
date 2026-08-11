/**
 * CyberShield - Website Security, HTTP Headers & Vulnerability Scanner
 * v2.0 - SSRF Protected, Weighted Scoring, Redirect Chain Tracking
 */

const axios = require('axios');
const { URL } = require('url');
const dns = require('dns').promises;
const http = require('http');
const https = require('https');

// ---------------------------------------------------------------------------
// SSRF Protection Blocklist
// ---------------------------------------------------------------------------

const PRIVATE_IP_PATTERNS = [
  // IPv4 loopback / wildcard
  /^127\./,
  /^0\.0\.0\.0$/,
  // RFC 1918 private ranges
  /^10\./,
  /^172\.(1[6-9]|2\d|3[01])\./,
  /^192\.168\./,
  // Link-local (AWS metadata & APIPA)
  /^169\.254\./,
  // CGNAT
  /^100\.(6[4-9]|[7-9]\d|1([01]\d|2[0-7]))\./,
  // Broadcast / reserved
  /^255\./,
  /^0\./
];

const PRIVATE_IPV6_PATTERNS = [
  /^::1$/,            // loopback
  /^fc/i,             // Unique local fc00::/7
  /^fd/i,             // Unique local fd00::/8
  /^fe80/i            // Link-local fe80::/10
];

const BLOCKED_HOSTNAMES = [
  'localhost',
  'metadata.google.internal',
  '169.254.169.254'
];

const BLOCKED_DOMAIN_SUFFIXES = ['.internal', '.local'];

/**
 * Checks whether an IP address string is a private/reserved address.
 * @param {string} ip
 * @returns {boolean}
 */
function isPrivateIp(ip) {
  if (!ip) return false;

  // Strip IPv6 scope id if present (e.g. fe80::1%eth0)
  const cleanIp = ip.split('%')[0];

  // IPv6 checks
  if (cleanIp.includes(':')) {
    return PRIVATE_IPV6_PATTERNS.some(p => p.test(cleanIp));
  }

  // IPv4 checks
  return PRIVATE_IP_PATTERNS.some(p => p.test(cleanIp));
}

/**
 * Validates a hostname against the SSRF blocklist (hostname-level checks only).
 * Returns an SSRF error object if blocked, or null if OK.
 * @param {string} hostname
 * @returns {{ ssrfBlocked: boolean, error: string } | null}
 */
function checkSsrfHostname(hostname) {
  const h = (hostname || '').toLowerCase();

  if (BLOCKED_HOSTNAMES.includes(h)) {
    return { ssrfBlocked: true, error: 'Internal/private network access blocked for security reasons.' };
  }

  for (const suffix of BLOCKED_DOMAIN_SUFFIXES) {
    if (h.endsWith(suffix)) {
      return { ssrfBlocked: true, error: 'Internal/private network access blocked for security reasons.' };
    }
  }

  // Block raw private IPv4 as hostname (e.g. http://192.168.1.1)
  if (isPrivateIp(h)) {
    return { ssrfBlocked: true, error: 'Internal/private network access blocked for security reasons.' };
  }

  return null;
}

// ---------------------------------------------------------------------------
// Weighted Security Scoring
// ---------------------------------------------------------------------------

const HEADER_WEIGHTS = {
  https:            25,
  hsts:             15,
  xFrameOptions:    10,
  xContentTypeOptions: 10,
  csp:              20,
  referrerPolicy:   10,
  serverBanner:     10   // awarded when server banner is NOT disclosed
};
// Total = 100

/**
 * Maps a 0-100 score to a human-readable risk level.
 * @param {number} score
 * @returns {string}
 */
function scoreToRiskLevel(score) {
  if (score >= 90) return 'Safe';
  if (score >= 75) return 'Low Risk';
  if (score >= 50) return 'Medium Risk';
  if (score >= 25) return 'High Risk';
  return 'Critical';
}

// ---------------------------------------------------------------------------
// Redirect-following helper (manual, up to maxRedirects)
// ---------------------------------------------------------------------------

/**
 * Performs an HTTP GET following redirects manually, capturing the chain.
 * Returns { finalResponse, redirectChain }.
 */
async function fetchWithRedirectChain(startUrl, maxRedirects = 3) {
  const redirectChain = [];
  let currentUrl = startUrl;
  let lastResponse = null;

  for (let i = 0; i <= maxRedirects; i++) {
    try {
      const response = await axios.get(currentUrl, {
        timeout: 8000,
        maxRedirects: 0,               // we handle redirects manually
        validateStatus: () => true,
        headers: { 'User-Agent': 'CyberShield-Security-Auditor/2.0' }
      });

      lastResponse = response;

      const status = response.status;
      if ([301, 302, 303, 307, 308].includes(status)) {
        const location = response.headers['location'];
        if (location && i < maxRedirects) {
          // Resolve relative redirects
          try {
            const nextUrl = new URL(location, currentUrl).href;
            redirectChain.push(currentUrl);
            currentUrl = nextUrl;
            continue;
          } catch (_) {
            break;
          }
        }
      }
      break; // non-redirect or max redirects exhausted
    } catch (err) {
      if (i === 0) throw err; // propagate first-request errors
      break;
    }
  }

  return { finalResponse: lastResponse, redirectChain };
}

// ---------------------------------------------------------------------------
// Main Scanner
// ---------------------------------------------------------------------------

/**
 * Performs a comprehensive website security audit.
 * SSRF-protected: blocks private/internal IPs and hostnames.
 *
 * @param {string} targetUrl
 * @returns {Promise<object>} Structured scan result
 */
async function scanWebsiteSecurity(targetUrl) {
  const startTime = Date.now();

  // ── 1. Normalise URL ──────────────────────────────────────────────────────
  let formattedUrl = (targetUrl || '').trim();
  if (!formattedUrl.startsWith('http://') && !formattedUrl.startsWith('https://')) {
    formattedUrl = 'https://' + formattedUrl;
  }

  let parsedUrl;
  try {
    parsedUrl = new URL(formattedUrl);
  } catch (err) {
    return {
      url: targetUrl,
      domain: null,
      resolvedIp: null,
      protocol: null,
      securityScore: 0,
      riskLevel: 'Critical',
      hasHttps: false,
      sslValid: false,
      redirectChain: [],
      headerChecks: {},
      missingHeaders: [],
      vulnerabilities: [{ title: 'Malformed URL', severity: 'HIGH', description: 'Invalid URL structure provided.', recommendation: 'Provide a valid website URL e.g. https://example.com' }],
      recommendations: ['Provide a valid website URL e.g. https://example.com'],
      scanDuration: Date.now() - startTime,
      scannedAt: new Date()
    };
  }

  const hostname = parsedUrl.hostname;

  // ── 2. SSRF Check – hostname level ────────────────────────────────────────
  const hostnameCheck = checkSsrfHostname(hostname);
  if (hostnameCheck) {
    return { ...hostnameCheck, url: formattedUrl, scanDuration: Date.now() - startTime, scannedAt: new Date() };
  }

  // ── 3. SSRF Check – DNS resolution ───────────────────────────────────────
  let resolvedIp = null;
  try {
    const dnsResult = await dns.lookup(hostname);
    resolvedIp = dnsResult.address;

    if (isPrivateIp(resolvedIp)) {
      return {
        ssrfBlocked: true,
        error: 'Internal/private network access blocked for security reasons.',
        url: formattedUrl,
        domain: hostname,
        resolvedIp,
        scanDuration: Date.now() - startTime,
        scannedAt: new Date()
      };
    }
  } catch (dnsErr) {
    // DNS failure is non-fatal; we continue and let the HTTP request fail naturally
  }

  // ── 4. Initialise result accumulators ────────────────────────────────────
  const isHttps = parsedUrl.protocol === 'https:';
  const vulnerabilities = [];
  const recommendations = [];
  const missingHeaders = [];
  let redirectChain = [];

  let headerChecks = {
    hsts: false,
    xFrameOptions: false,
    xContentTypeOptions: false,
    csp: false,
    referrerPolicy: false,
    permissionsPolicy: false,
    serverBanner: false   // true = banner NOT disclosed (good)
  };

  // ── 5. HTTP request + redirect chain ─────────────────────────────────────
  try {
    const { finalResponse, redirectChain: chain } = await fetchWithRedirectChain(parsedUrl.href);
    redirectChain = chain;

    const headers = (finalResponse && finalResponse.headers) || {};

    // Read headers
    const hsts     = headers['strict-transport-security'];
    const xfo      = headers['x-frame-options'];
    const xcto     = headers['x-content-type-options'];
    const csp      = headers['content-security-policy'];
    const rp       = headers['referrer-policy'];
    const pp       = headers['permissions-policy'] || headers['feature-policy'];
    const server   = headers['server'];

    headerChecks = {
      hsts:                 !!hsts,
      xFrameOptions:        !!xfo,
      xContentTypeOptions:  !!xcto,
      csp:                  !!csp,
      referrerPolicy:       !!rp,
      permissionsPolicy:    !!pp,
      serverBanner:         !server   // true = NOT disclosing (secure)
    };

    // Vulnerability: no HTTPS
    if (!isHttps) {
      vulnerabilities.push({
        title: 'Missing HTTPS Encryption',
        severity: 'HIGH',
        description: 'Traffic transmitted over plain HTTP can be intercepted via Man-in-the-Middle (MitM) attacks.',
        recommendation: 'Install a valid TLS/SSL certificate and enforce HTTPS redirection.'
      });
      recommendations.push('Install a valid TLS/SSL certificate and enforce HTTPS redirection.');
    }

    // Vulnerability: missing HSTS
    if (!hsts) {
      missingHeaders.push('Strict-Transport-Security');
      vulnerabilities.push({
        title: 'Missing HSTS Header',
        severity: 'MEDIUM',
        description: 'Without HSTS the site can be downgraded to plain HTTP by an attacker.',
        recommendation: 'Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'
      });
      recommendations.push('Add HSTS header (Strict-Transport-Security) to prevent HTTP downgrade attacks.');
    }

    // Vulnerability: missing X-Frame-Options
    if (!xfo) {
      missingHeaders.push('X-Frame-Options');
      vulnerabilities.push({
        title: 'Clickjacking Vulnerability (Missing X-Frame-Options)',
        severity: 'MEDIUM',
        description: 'Site can be embedded in an iframe on malicious websites for clickjacking attacks.',
        recommendation: 'Set X-Frame-Options: DENY or SAMEORIGIN.'
      });
      recommendations.push('Set X-Frame-Options: DENY or SAMEORIGIN.');
    }

    // Vulnerability: missing X-Content-Type-Options
    if (!xcto) {
      missingHeaders.push('X-Content-Type-Options');
      vulnerabilities.push({
        title: 'Missing X-Content-Type-Options',
        severity: 'LOW',
        description: 'Without nosniff, browsers may MIME-sniff responses, enabling content injection.',
        recommendation: 'Set X-Content-Type-Options: nosniff'
      });
      recommendations.push('Set X-Content-Type-Options: nosniff to block MIME-type sniffing.');
    }

    // Vulnerability: missing CSP
    if (!csp) {
      missingHeaders.push('Content-Security-Policy');
      vulnerabilities.push({
        title: 'Missing Content Security Policy (CSP)',
        severity: 'HIGH',
        description: 'Without CSP, site is exposed to Cross-Site Scripting (XSS) and data injection.',
        recommendation: 'Implement a strong Content-Security-Policy header.'
      });
      recommendations.push('Implement a strong Content-Security-Policy header.');
    }

    // Info: missing Referrer-Policy
    if (!rp) {
      missingHeaders.push('Referrer-Policy');
      recommendations.push('Add Referrer-Policy: strict-origin-when-cross-origin to limit referrer leakage.');
    }

    // Info: missing Permissions-Policy
    if (!pp) {
      missingHeaders.push('Permissions-Policy');
      recommendations.push('Add Permissions-Policy header to control browser feature access (camera, mic, etc.).');
    }

    // Vulnerability: server banner disclosure
    if (server) {
      vulnerabilities.push({
        title: 'Server Information Disclosure',
        severity: 'LOW',
        description: `Server banner exposed: "${server}". Attackers use banner grabbing to target version-specific CVEs.`,
        recommendation: 'Hide or obscure the Server HTTP response header.'
      });
      recommendations.push('Hide or obscure the Server HTTP response header.');
    }

  } catch (axiosErr) {
    vulnerabilities.push({
      title: 'Connection Failed / Host Unreachable',
      severity: 'MEDIUM',
      description: `Could not complete live HTTP audit: ${axiosErr.message}`,
      recommendation: 'Ensure the server is reachable and not blocking automated scanners.'
    });
  }

  // ── 6. Weighted Security Score ────────────────────────────────────────────
  let securityScore = 0;
  if (isHttps)                        securityScore += HEADER_WEIGHTS.https;
  if (headerChecks.hsts)              securityScore += HEADER_WEIGHTS.hsts;
  if (headerChecks.xFrameOptions)     securityScore += HEADER_WEIGHTS.xFrameOptions;
  if (headerChecks.xContentTypeOptions) securityScore += HEADER_WEIGHTS.xContentTypeOptions;
  if (headerChecks.csp)               securityScore += HEADER_WEIGHTS.csp;
  if (headerChecks.referrerPolicy)    securityScore += HEADER_WEIGHTS.referrerPolicy;
  if (headerChecks.serverBanner)      securityScore += HEADER_WEIGHTS.serverBanner;

  securityScore = Math.max(0, Math.min(100, securityScore));
  const riskLevel = scoreToRiskLevel(securityScore);

  // ── 7. Return comprehensive result ────────────────────────────────────────
  return {
    url: formattedUrl,
    domain: hostname,
    resolvedIp,
    protocol: parsedUrl.protocol,
    securityScore,
    riskLevel,
    hasHttps: isHttps,
    sslValid: isHttps,
    redirectChain,
    headerChecks,
    missingHeaders,
    vulnerabilities,
    recommendations,
    scanDuration: Date.now() - startTime,
    scannedAt: new Date()
  };
}

/**
 * Helper to check if a URL or domain points to a private/SSRF target.
 * @param {string} inputUrl
 * @returns {boolean}
 */
function isSSRFUrl(inputUrl) {
  try {
    let target = (inputUrl || '').trim();
    if (!target.startsWith('http://') && !target.startsWith('https://')) {
      target = 'https://' + target;
    }
    const parsed = new URL(target);
    const host = parsed.hostname.toLowerCase();
    
    // Check blocklist
    if (BLOCKED_HOSTNAMES.includes(host)) return true;
    for (const suffix of BLOCKED_DOMAIN_SUFFIXES) {
      if (host.endsWith(suffix)) return true;
    }
    // Check private IP
    if (isPrivateIp(host)) return true;
    
    return false;
  } catch (e) {
    return true; // Unparseable format - treat as unsafe
  }
}

module.exports = {
  scanWebsiteSecurity,
  checkSsrfHostname,
  isPrivateIp,
  isSSRFUrl
};
