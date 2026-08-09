const { extractDomainInfo } = require('../utils/domainInfo');

describe('Domain Info Extractor', () => {
  test('extracts domain from URL', () => {
    const result = extractDomainInfo('https://www.example.com/path');
    expect(result.domain).toBe('www.example.com');
    expect(result.protocol).toBe('https:');
    expect(result.isHttps).toBe(true);
  });

  test('handles URLs without protocol', () => {
    const result = extractDomainInfo('example.com');
    expect(result.domain).toBe('example.com');
    expect(result.isHttps).toBe(true);
  });

  test('detects IP-based URLs', () => {
    const result = extractDomainInfo('http://192.168.1.1');
    expect(result.suspiciousPatterns).toContain('IP-based URL (no domain name)');
  });

  test('detects excessive subdomains', () => {
    const result = extractDomainInfo('https://a.b.c.d.e.example.com');
    expect(result.subdomainCount).toBeGreaterThan(3);
    expect(result.suspiciousPatterns.some(p => p.includes('Excessive subdomains'))).toBe(true);
  });

  test('detects suspicious TLDs', () => {
    const result = extractDomainInfo('https://example.xyz');
    expect(result.suspiciousPatterns.some(p => p.includes('High-risk TLD'))).toBe(true);
  });

  test('detects Punycode/IDN', () => {
    const result = extractDomainInfo('https://xn--example.com');
    expect(result.suspiciousPatterns.some(p => p.includes('Homograph'))).toBe(true);
  });

  test('detects mixed script homographs', () => {
    const result = extractDomainInfo('https://exаmple.com'); // Cyrillic 'а'
    expect(result.suspiciousPatterns.some(p => p.includes('Homograph'))).toBe(true);
  });

  test('handles invalid URLs', () => {
    const result = extractDomainInfo('not a url at all');
    expect(result.domain).toBeNull();
    expect(result.suspiciousPatterns).toContain('Invalid URL structure');
  });
});