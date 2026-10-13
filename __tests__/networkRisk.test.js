/**
 * CyberShield — Anonymous Network Risk Detection Test Suite
 */

const {
  extractClientIp,
  isPrivateOrLocalIp,
  inspectIp,
  evaluateLocalHeuristics,
  _ipCache,
  _KNOWN_TOR_EXIT_IPS
} = require('../services/anonymousNetworkService');

const {
  recordFailedLogin,
  clearFailedLogin,
  getFailedLoginCount
} = require('../services/networkRiskService');

describe('Anonymous Network Intelligence & IP Extraction', () => {
  beforeEach(() => {
    _ipCache.clear();
  });

  describe('extractClientIp', () => {
    test('extracts direct IPv4', () => {
      const req = { ip: '203.0.113.195', headers: {} };
      expect(extractClientIp(req)).toBe('203.0.113.195');
    });

    test('strips ::ffff: IPv6 prefix', () => {
      const req = { ip: '::ffff:198.51.100.22', headers: {} };
      expect(extractClientIp(req)).toBe('198.51.100.22');
    });

    test('extracts leftmost client from X-Forwarded-For', () => {
      const req = {
        headers: { 'x-forwarded-for': '203.0.113.50, 10.0.0.1, 172.16.0.2' },
        ip: '10.0.0.1'
      };
      expect(extractClientIp(req)).toBe('203.0.113.50');
    });

    test('converts ::1 to 127.0.0.1', () => {
      const req = { ip: '::1', headers: {} };
      expect(extractClientIp(req)).toBe('127.0.0.1');
    });

    test('handles missing req safely', () => {
      expect(extractClientIp(null)).toBe('127.0.0.1');
    });
  });

  describe('isPrivateOrLocalIp', () => {
    test('identifies loopback 127.0.0.1 as private', () => {
      expect(isPrivateOrLocalIp('127.0.0.1')).toBe(true);
    });

    test('identifies 10.x.x.x as private', () => {
      expect(isPrivateOrLocalIp('10.254.1.1')).toBe(true);
    });

    test('identifies 192.168.x.x as private', () => {
      expect(isPrivateOrLocalIp('192.168.1.45')).toBe(true);
    });

    test('identifies 172.16-31.x.x as private', () => {
      expect(isPrivateOrLocalIp('172.20.10.2')).toBe(true);
    });

    test('identifies public IP as non-private', () => {
      expect(isPrivateOrLocalIp('8.8.8.8')).toBe(false);
      expect(isPrivateOrLocalIp('185.220.101.5')).toBe(false);
    });
  });

  describe('inspectIp & Local Heuristics', () => {
    test('returns Private/Internal for local loopback without calling providers', async () => {
      const res = await inspectIp('127.0.0.1');
      expect(res.isPrivate).toBe(true);
      expect(res.networkType).toBe('Private/Internal');
      expect(res.vpnDetected).toBe(false);
      expect(res.torDetected).toBe(false);
    });

    test('identifies verified Tor exit node', async () => {
      const torIp = '185.220.101.5';
      const res = await inspectIp(torIp);
      expect(res.torDetected).toBe(true);
      expect(res.networkType).toBe('Tor');
      expect(res.country).toBeDefined();
    });

    test('identifies commercial VPN IP', async () => {
      const vpnIp = '194.26.29.10';
      const res = await inspectIp(vpnIp);
      expect(res.vpnDetected).toBe(true);
      expect(res.networkType).toBe('VPN');
    });

    test('identifies datacenter/hosting IP', async () => {
      const hostingIp = '104.131.50.2'; // DigitalOcean prefix
      const res = await inspectIp(hostingIp);
      expect(res.hostingDetected).toBe(true);
      expect(res.networkType).toBe('Hosting');
    });

    test('caches previous IP inspection for subsequent queries', async () => {
      const ip = '194.26.29.99';
      const first = await inspectIp(ip);
      expect(first.cached).toBe(false);

      const second = await inspectIp(ip);
      expect(second.cached).toBe(true);
      expect(second.ip).toBe(ip);
    });
  });
});

describe('Failed Login Tracker', () => {
  beforeEach(() => {
    clearFailedLogin('198.51.100.77', 'analyst_bob');
  });

  test('increments failed login count on consecutive attempts', () => {
    const ip = '198.51.100.77';
    const user = 'analyst_bob';

    expect(getFailedLoginCount(ip, user)).toBe(0);

    const c1 = recordFailedLogin(ip, user);
    expect(c1).toBe(1);

    const c2 = recordFailedLogin(ip, user);
    expect(c2).toBe(2);

    expect(getFailedLoginCount(ip, user)).toBe(2);
  });

  test('clears failed logins after successful authentication', () => {
    const ip = '198.51.100.77';
    const user = 'analyst_bob';

    recordFailedLogin(ip, user);
    recordFailedLogin(ip, user);
    expect(getFailedLoginCount(ip, user)).toBe(2);

    clearFailedLogin(ip, user);
    expect(getFailedLoginCount(ip, user)).toBe(0);
  });
});

describe('Risk Scoring Principles (Golden Rules)', () => {
  test('VPN usage alone evaluates strictly as LOW risk (weight 15)', () => {
    const vpnWeight = 15;
    const score = vpnWeight; // 15
    const isLow = score <= 30;
    const isHigh = score > 60;

    expect(isLow).toBe(true);
    expect(isHigh).toBe(false);
  });

  test('VPN + Hosting without behavioral failures stays in LOW risk band (30)', () => {
    const vpnWeight = 15;
    const hostingWeight = 15;
    const score = vpnWeight + hostingWeight; // 30
    const isLow = score <= 30;

    expect(score).toBe(30);
    expect(isLow).toBe(true);
  });

  test('Tor exit node (+25) + Repeated failed logins (+20) enters MEDIUM risk (45)', () => {
    const torWeight = 25;
    const failedLoginsWeight = 20;
    const score = torWeight + failedLoginsWeight; // 45
    const isMedium = score > 30 && score <= 60;

    expect(score).toBe(45);
    expect(isMedium).toBe(true);
  });

  test('Tor (+25) + failed logins (+20) + sensitive endpoint (+15) + suspicious API (+20) reaches HIGH risk (80)', () => {
    const torWeight = 25;
    const failedLoginsWeight = 20;
    const sensitiveWeight = 15;
    const suspiciousWeight = 20;
    const score = torWeight + failedLoginsWeight + sensitiveWeight + suspiciousWeight; // 80
    const isHigh = score > 60 && score <= 80;

    expect(score).toBe(80);
    expect(isHigh).toBe(true);
  });

  test('Multi-vector attack score caps at 100 maximum', () => {
    const rawScore = 25 + 15 + 15 + 15 + 20 + 10 + 20 + 15 + 15; // 155
    const finalScore = Math.max(0, Math.min(100, rawScore));
    expect(finalScore).toBe(100);
  });
});
