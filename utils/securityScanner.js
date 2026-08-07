/**
 * CyberShield - Website Security, HTTP Headers & Vulnerability Scanner
 */

const axios = require('axios');
const { URL } = require('url');

async function scanWebsiteSecurity(targetUrl) {
  let formattedUrl = targetUrl.trim();
  if (!formattedUrl.startsWith('http://') && !formattedUrl.startsWith('https://')) {
    formattedUrl = 'https://' + formattedUrl;
  }

  let parsedUrl;
  try {
    parsedUrl = new URL(formattedUrl);
  } catch (err) {
    return {
      url: targetUrl,
      securityScore: 0,
      riskLevel: 'High Risk',
      hasHttps: false,
      sslValid: false,
      headers: {},
      vulnerabilities: [{ title: 'Malformed URL', severity: 'HIGH', description: 'Invalid URL structure provided.' }],
      recommendations: ['Provide a valid website URL e.g. https://example.com']
    };
  }

  const isHttps = parsedUrl.protocol === 'https:';
  const vulnerabilities = [];
  const recommendations = [];
  const missingHeaders = [];
  let headerChecks = {};

  try {
    const response = await axios.get(parsedUrl.href, {
      timeout: 5000,
      headers: { 'User-Agent': 'CyberShield-Security-Auditor/1.0' },
      validateStatus: () => true
    });

    const headers = response.headers || {};

    // Check Security Headers
    const hsts = headers['strict-transport-security'];
    const xfo = headers['x-frame-options'];
    const xcto = headers['x-content-type-options'];
    const csp = headers['content-security-policy'];
    const rp = headers['referrer-policy'];
    const server = headers['server'];

    headerChecks = {
      hsts: !!hsts,
      xFrameOptions: !!xfo,
      xContentTypeOptions: !!xcto,
      csp: !!csp,
      referrerPolicy: !!rp
    };

    if (!isHttps) {
      vulnerabilities.push({
        title: 'Missing HTTPS Encryption',
        severity: 'HIGH',
        description: 'Traffic transmitted over plain HTTP can be intercepted via Man-in-the-Middle (MitM) attacks.'
      });
      recommendations.push('Install a valid TLS/SSL certificate and enforce HTTPS redirection.');
    }

    if (!hsts) {
      missingHeaders.push('Strict-Transport-Security');
      recommendations.push('Add HSTS header (Strict-Transport-Security) to prevent HTTP downgrade attacks.');
    }

    if (!xfo) {
      missingHeaders.push('X-Frame-Options');
      vulnerabilities.push({
        title: 'Clickjacking Vulnerability (Missing X-Frame-Options)',
        severity: 'MEDIUM',
        description: 'Site can be embedded in an iframe on malicious websites for clickjacking attacks.'
      });
      recommendations.push('Set X-Frame-Options: DENY or SAMEORIGIN.');
    }

    if (!xcto) {
      missingHeaders.push('X-Content-Type-Options');
      recommendations.push('Set X-Content-Type-Options: nosniff to block MIME-type sniffing.');
    }

    if (!csp) {
      missingHeaders.push('Content-Security-Policy');
      vulnerabilities.push({
        title: 'Missing Content Security Policy (CSP)',
        severity: 'HIGH',
        description: 'Without CSP, site is exposed to Cross-Site Scripting (XSS) and data injection.'
      });
      recommendations.push('Implement a strong Content-Security-Policy header.');
    }

    if (server) {
      vulnerabilities.push({
        title: 'Server Information Disclosure',
        severity: 'LOW',
        description: `Server banner exposed: ${server}. Attackers use banner grabbing to target version-specific CVEs.`
      });
      recommendations.push('Hide or obscure the Server HTTP response header.');
    }

  } catch (axiosErr) {
    vulnerabilities.push({
      title: 'Connection Timed Out / Host Unreachable',
      severity: 'MEDIUM',
      description: `Could not complete live HTTP audit: ${axiosErr.message}`
    });
  }

  // Calculate Security Score (0 to 100)
  let score = 100;
  if (!isHttps) score -= 30;
  score -= (missingHeaders.length * 10);
  score = Math.max(10, Math.min(100, score));

  let riskLevel = 'Safe';
  if (score < 50) riskLevel = 'High Risk';
  else if (score < 75) riskLevel = 'Medium Risk';

  return {
    url: parsedUrl.href,
    securityScore: score,
    riskLevel,
    hasHttps: isHttps,
    sslValid: isHttps,
    missingHeaders,
    headerChecks,
    vulnerabilities,
    recommendations
  };
}

module.exports = {
  scanWebsiteSecurity
};
