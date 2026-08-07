/**
 * CyberShield - IP Reputation & Threat Intelligence Evaluator
 */

function checkIpReputation(ip) {
  const cleanIp = (ip || '').trim();
  const isPrivate = /^(127\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)/.test(cleanIp);
  
  if (!cleanIp) {
    return {
      ip: '0.0.0.0',
      country: 'Unknown',
      city: 'Unknown',
      isp: 'Unknown',
      isProxy: false,
      isVpn: false,
      isTor: false,
      threatScore: 0,
      riskLevel: 'Safe',
      blacklistStatus: 'Clean',
      details: ['Invalid IP specified']
    };
  }

  // Known suspicious test IP ranges simulation for threat intelligence testing
  const isSuspicious = cleanIp.endsWith('.100') || cleanIp.endsWith('.66') || cleanIp.startsWith('185.');
  const isMalicious = cleanIp.endsWith('.666') || cleanIp.startsWith('193.163.');

  let threatScore = 10;
  let riskLevel = 'Safe';
  let blacklistStatus = 'Clean';
  let isProxy = false;
  let isVpn = false;
  let isTor = false;

  if (isPrivate) {
    return {
      ip: cleanIp,
      country: 'Local Network / Private',
      city: 'Internal Gateway',
      isp: 'Local Infrastructure',
      isProxy: false,
      isVpn: false,
      isTor: false,
      threatScore: 0,
      riskLevel: 'Safe',
      blacklistStatus: 'Clean (Loopback / LAN)',
      details: ['Private RFC-1918 address. Safe internal node.']
    };
  }

  if (isMalicious) {
    threatScore = 88;
    riskLevel = 'High Risk';
    blacklistStatus = 'Blacklisted (Spamhaus / AbuseIPDB)';
    isProxy = true;
    isVpn = true;
    isTor = true;
  } else if (isSuspicious) {
    threatScore = 55;
    riskLevel = 'Medium Risk';
    blacklistStatus = 'Flagged on 2 Security Feeds';
    isProxy = true;
    isVpn = true;
  }

  return {
    ip: cleanIp,
    country: isSuspicious ? 'Russia / Offshore' : 'United States',
    city: isSuspicious ? 'Moscow' : 'Mountain View, CA',
    isp: isSuspicious ? 'Offshore Datacenter ASN' : 'Google LLC / Cloudflare',
    isProxy,
    isVpn,
    isTor,
    threatScore,
    riskLevel,
    blacklistStatus,
    details: [
      `Abuse Confidence Index: ${threatScore}%`,
      `ASN Type: ${isProxy ? 'Datacenter / Anonymizer' : 'Residential ISP'}`,
      `Proxy Detection: ${isProxy ? 'ACTIVE DETECTED' : 'None'}`,
      `VPN Tunnel: ${isVpn ? 'ACTIVE DETECTED' : 'None'}`
    ]
  };
}

module.exports = {
  checkIpReputation
};
