const { analyzePassword, generateStrongPassword } = require('../utils/passwordAnalyzer');

describe('Password Analyzer', () => {
  describe('analyzePassword', () => {
    test('returns correct structure for empty password', () => {
      const result = analyzePassword('');
      expect(result).toHaveProperty('score', 0);
      expect(result).toHaveProperty('strength', 'Very Weak');
      expect(result).toHaveProperty('entropyBits', 0);
      expect(result).toHaveProperty('timeToCrack', 'Instant');
      expect(result.checks).toHaveProperty('length', false);
    });

    test('analyzes weak password correctly', () => {
      const result = analyzePassword('123');
      expect(result.score).toBeLessThanOrEqual(2);
      expect(result.strength).toMatch(/Very Weak|Weak/);
      expect(result.checks.length).toBe(false);
      expect(result.checks.hasNumbers).toBe(true);
      expect(result.checks.hasUppercase).toBe(false);
      expect(result.checks.hasLowercase).toBe(false);
      expect(result.checks.hasSymbols).toBe(false);
    });

    test('analyzes medium password correctly', () => {
      const result = analyzePassword('Password123');
      expect(result.score).toBeGreaterThanOrEqual(2);
      expect(result.checks.hasUppercase).toBe(true);
      expect(result.checks.hasLowercase).toBe(true);
      expect(result.checks.hasNumbers).toBe(true);
      expect(result.checks.hasSymbols).toBe(false);
    });

    test('analyzes strong password correctly', () => {
      const result = analyzePassword('Str0ng!Passw0rd');
      expect(result.score).toBeGreaterThanOrEqual(3);
      expect(result.strength).toMatch(/Medium|Strong|Very Strong/);
      expect(result.checks.hasSymbols).toBe(true);
      expect(result.checks.length).toBe(true);
    });

    test('detects common passwords', () => {
      const result = analyzePassword('password');
      expect(result.checks.noDictionaryWords).toBe(false);
      expect(result.suggestions.some(s => s.includes('leak dictionaries'))).toBe(true);
    });

    test('detects repeated characters', () => {
      const result = analyzePassword('aaaBBB123');
      expect(result.checks.noRepeatedChars).toBe(false);
      expect(result.suggestions.some(s => s.includes('repeating'))).toBe(true);
    });

    test('detects sequential patterns', () => {
      const result = analyzePassword('abc123XYZ');
      expect(result.checks.noSequentialNums).toBe(false);
      expect(result.suggestions.some(s => s.includes('sequential'))).toBe(true);
    });

    test('entropy calculation is reasonable', () => {
      const weak = analyzePassword('123');
      const strong = analyzePassword('VeryStr0ng!Passw0rd123');
      expect(strong.entropyBits).toBeGreaterThan(weak.entropyBits);
    });
  });

  describe('generateStrongPassword', () => {
    test('generates password of correct length', () => {
      const pwd = generateStrongPassword(16);
      expect(pwd.length).toBe(16);
    });

    test('generates password with all character types', () => {
      const pwd = generateStrongPassword(16);
      expect(/[A-Z]/.test(pwd)).toBe(true);
      expect(/[a-z]/.test(pwd)).toBe(true);
      expect(/[0-9]/.test(pwd)).toBe(true);
      expect(/[^A-Za-z0-9]/.test(pwd)).toBe(true);
    });

    test('generates different passwords each call', () => {
      const pwd1 = generateStrongPassword(16);
      const pwd2 = generateStrongPassword(16);
      expect(pwd1).not.toBe(pwd2);
    });

    test('generated password is analyzed as strong', () => {
      const pwd = generateStrongPassword(16);
      const analysis = analyzePassword(pwd);
      expect(analysis.score).toBeGreaterThanOrEqual(3);
      expect(analysis.checks.length).toBe(true);
      expect(analysis.checks.hasUppercase).toBe(true);
      expect(analysis.checks.hasLowercase).toBe(true);
      expect(analysis.checks.hasNumbers).toBe(true);
      expect(analysis.checks.hasSymbols).toBe(true);
    });
  });
});