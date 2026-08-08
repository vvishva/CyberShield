/**
 * CyberShield - Domain Info Extractor
 * Pure structural URL analysis — no network requests made.
 */

const { URL } = require('url');

const SUSPICIOUS_TLDS = new Set(['.xyz', '.tk', '.ml', '.ga', '.cf', '.gq']);

/**
 * Checks if a string contains potential homograph / IDN homoglyph characters.
 * Looks for mixed scripts or Punycode encoding (xn--).
 * @param {string} domain
 * @returns {boolean}
 */
function hasHomographIndicators(domain) {
  // Punycode encoding is a strong indicator of IDN homograph attempts
  if (/xn--/i.test(domain)) return true;

  // Mixed Latin + Cyrillic / Greek characters in same label
  const labels = domain.split('.');
  for (const label of labels) {
    const hasCyrillic = /[\u0400-\u04FF]/.test(label);
    const hasGreek    = /[\u0370-\u03FF]/.test(label);
    const hasLatin    = /[a-zA-Z]/.test(label);
    if ((hasCyrillic || hasGreek) && hasLatin) return true;
  }

  return false;
}

/**
 * Extracts and analyses structural domain information from a URL.
 * Never makes network requests — purely syntactic/structural analysis.
 *
 * @param {string} rawUrl  - The URL string to analyse (with or without scheme).
 * @returns {{
 *   domain: string|null,
 *   protocol: string|null,
 *   port: string|null,
 *   path: string,
 *   isHttps: boolean,
 *   hasSubdomain: boolean,
 *   subdomainCount: number,
 *   suspiciousPatterns: string[]
 * }}
 */
function extractDomainInfo(rawUrl) {
  let normalized = (rawUrl || '').trim();
  if (!normalized.startsWith('http://') && !normalized.startsWith('https://')) {
    normalized = 'https://' + normalized;
  }

  let parsed;
  try {
    parsed = new URL(normalized);
  } catch (_) {
    return {
      domain: null,
      protocol: null,
      port: null,
      path: '/',
      isHttps: false,
      hasSubdomain: false,
      subdomainCount: 0,
      suspiciousPatterns: ['Invalid URL structure']
    };
  }

  const hostname  = parsed.hostname;
  const protocol  = parsed.protocol;          // 'https:' | 'http:'
  const port      = parsed.port || null;
  const path      = parsed.pathname;
  const isHttps   = protocol === 'https:';

  // Subdomain analysis (split by dots, last two parts = registrable domain)
  const labels = hostname.split('.');
  // For an IP address labels will all be numeric — we handle that separately
  const isIpBased = /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname);
  const subdomainCount = isIpBased ? 0 : Math.max(0, labels.length - 2);
  const hasSubdomain   = subdomainCount > 0;

  // Suspicious pattern detection
  const suspiciousPatterns = [];

  // IP-based URL
  if (isIpBased) {
    suspiciousPatterns.push('IP-based URL (no domain name)');
  }

  // Excessive subdomains (>3 levels)
  if (subdomainCount > 3) {
    suspiciousPatterns.push(`Excessive subdomains (${subdomainCount} levels)`);
  }

  // Homograph / IDN indicators
  if (hasHomographIndicators(hostname)) {
    suspiciousPatterns.push('Homograph / IDN Punycode indicators detected');
  }

  // Very long domain (>50 chars)
  if (hostname.length > 50) {
    suspiciousPatterns.push(`Unusually long domain name (${hostname.length} characters)`);
  }

  // Suspicious TLD
  const tld = labels.length >= 2 ? '.' + labels[labels.length - 1].toLowerCase() : '';
  if (SUSPICIOUS_TLDS.has(tld)) {
    suspiciousPatterns.push(`High-risk TLD detected: ${tld}`);
  }

  return {
    domain: hostname,
    protocol,
    port,
    path,
    isHttps,
    hasSubdomain,
    subdomainCount,
    suspiciousPatterns
  };
}

module.exports = { extractDomainInfo };
