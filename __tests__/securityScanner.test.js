const { scanWebsiteSecurity, checkSsrfHostname, isPrivateIp } = require('../utils/securityScanner');

describe('Security Scanner', () => {
  describe('isPrivateIp', () => {
    test('identifies IPv4 loopback', () => {
      expect(isPrivateIp('127.0.0.1')).toBe(true);
      expect(isPrivateIp('127.255.255.255')).toBe(true);
    });

    test('identifies RFC 1918 private ranges', () => {
      expect(isPrivateIp('10.0.0.1')).toBe(true);
      expect(isPrivateIp('10.255.255.255')).toBe(true);
      expect(isPrivateIp('172.16.0.1')).toBe(true);
      expect(isPrivateIp('172.31.255.255')).toBe(true);
      expect(isPrivateIp('192.168.0.1')).toBe(true);
      expect(isPrivateIp('192.168.255.255')).toBe(true);
    });

    test('identifies link-local', () => {
      expect(isPrivateIp('169.254.0.1')).toBe(true);
    });

    test('identifies CGNAT', () => {
      expect(isPrivateIp('100.64.0.1')).toBe(true);
      expect(isPrivateIp('100.127.255.255')).toBe(true);
    });

    test('identifies IPv6 private', () => {
      expect(isPrivateIp('::1')).toBe(true);
      expect(isPrivateIp('fc00::1')).toBe(true);
      expect(isPrivateIp('fd00::1')).toBe(true);
      expect(isPrivateIp('fe80::1')).toBe(true);
    });

    test('allows public IPs', () => {
      expect(isPrivateIp('8.8.8.8')).toBe(false);
      expect(isPrivateIp('1.1.1.1')).toBe(false);
      expect(isPrivateIp('2001:4860:4860::8888')).toBe(false);
    });
  });

  describe('checkSsrfHostname', () => {
    test('blocks localhost', () => {
      const result = checkSsrfHostname('localhost');
      expect(result).not.toBeNull();
      expect(result.ssrfBlocked).toBe(true);
    });

    test('blocks metadata.google.internal', () => {
      const result = checkSsrfHostname('metadata.google.internal');
      expect(result).not.toBeNull();
      expect(result.ssrfBlocked).toBe(true);
    });

    test('blocks .internal domains', () => {
      const result = checkSsrfHostname('server.internal');
      expect(result).not.toBeNull();
      expect(result.ssrfBlocked).toBe(true);
    });

    test('blocks .local domains', () => {
      const result = checkSsrfHostname('server.local');
      expect(result).not.toBeNull();
      expect(result.ssrfBlocked).toBe(true);
    });

    test('blocks private IPs as hostname', () => {
      const result = checkSsrfHostname('192.168.1.1');
      expect(result).not.toBeNull();
      expect(result.ssrfBlocked).toBe(true);
    });

    test('allows public hostnames', () => {
      const result = checkSsrfHostname('google.com');
      expect(result).toBeNull();
    });

    test('allows public IPs', () => {
      const result = checkSsrfHostname('8.8.8.8');
      expect(result).toBeNull();
    });
  });

  describe('scanWebsiteSecurity', () => {
    test('handles malformed URLs', async () => {
      const result = await scanWebsiteSecurity('not-a-url');
      expect(result.url).toBe('not-a-url');
      expect(result.riskLevel).toBe('Critical');
      expect(result.vulnerabilities.some(v => v.title === 'Malformed URL')).toBe(true);
    });

    test('handles URLs without protocol', async () => {
      const result = await scanWebsiteSecurity('example.com');
      expect(result.url).toMatch(/^https:\/\//);
    });
  });
});