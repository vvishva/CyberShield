const { checkIpReputation } = require('../utils/ipChecker');

describe('IP Reputation Checker', () => {
  test('handles empty IP', () => {
    const result = checkIpReputation('');
    expect(result.ip).toBe('0.0.0.0');
    expect(result.riskLevel).toBe('Safe');
  });

  test('identifies private IPs', () => {
    const result = checkIpReputation('192.168.1.1');
    expect(result.country).toBe('Local Network / Private');
    expect(result.riskLevel).toBe('Safe');
    expect(result.blacklistStatus).toContain('Loopback / LAN');
  });

  test('identifies localhost', () => {
    const result = checkIpReputation('127.0.0.1');
    expect(result.riskLevel).toBe('Safe');
  });

  test('returns structured response for public IPs', () => {
    const result = checkIpReputation('8.8.8.8');
    expect(result).toHaveProperty('ip');
    expect(result).toHaveProperty('country');
    expect(result).toHaveProperty('city');
    expect(result).toHaveProperty('isp');
    expect(result).toHaveProperty('isProxy');
    expect(result).toHaveProperty('isVpn');
    expect(result).toHaveProperty('isTor');
    expect(result).toHaveProperty('threatScore');
    expect(result).toHaveProperty('riskLevel');
    expect(result).toHaveProperty('blacklistStatus');
    expect(result).toHaveProperty('details');
  });
});