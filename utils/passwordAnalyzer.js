/**
 * CyberShield - Password Strength & Entropy Analyzer
 */

const commonPasswords = [
  'password', '123456', '123456789', 'qwerty', '12345678', '111111', 
  '1234567', 'dragon', 'welcome', 'admin', 'cybershield', 'iloveyou', 
  'sunshine', 'princess', 'football', 'charlie', 'donald', 'monkey'
];

function analyzePassword(password) {
  if (!password) {
    return {
      score: 0,
      strength: 'Very Weak',
      entropyBits: 0,
      timeToCrack: 'Instant',
      checks: {
        length: false,
        hasUppercase: false,
        hasLowercase: false,
        hasNumbers: false,
        hasSymbols: false,
        noDictionaryWords: true,
        noRepeatedChars: true,
        noSequentialNums: true
      },
      suggestions: ['Please enter a password to analyze.']
    };
  }

  const length = password.length;
  const hasUppercase = /[A-Z]/.test(password);
  const hasLowercase = /[a-z]/.test(password);
  const hasNumbers = /[0-9]/.test(password);
  const hasSymbols = /[^A-Za-z0-9]/.test(password);
  const isCommon = commonPasswords.includes(password.toLowerCase());
  const hasRepeated = /(.)\1{2,}/.test(password);
  const hasSequential = /(012|123|234|345|456|567|678|789|890|abc|bcd|cde)/i.test(password);

  // Calculate Character Pool Size
  let poolSize = 0;
  if (hasLowercase) poolSize += 26;
  if (hasUppercase) poolSize += 26;
  if (hasNumbers) poolSize += 10;
  if (hasSymbols) poolSize += 32;

  // Calculate Entropy: E = L * log2(R)
  let entropy = length * Math.log2(poolSize || 1);
  if (isCommon) entropy = Math.min(entropy, 10);
  if (hasRepeated) entropy -= 5;
  if (hasSequential) entropy -= 5;
  entropy = Math.max(0, Math.round(entropy));

  // Determine Strength & Rating
  let strength = 'Very Weak';
  let score = 1;

  if (entropy < 28 || isCommon) {
    strength = 'Very Weak';
    score = 1;
  } else if (entropy < 40) {
    strength = 'Weak';
    score = 2;
  } else if (entropy < 60) {
    strength = 'Medium';
    score = 3;
  } else if (entropy < 80) {
    strength = 'Strong';
    score = 4;
  } else {
    strength = 'Very Strong';
    score = 5;
  }

  // Estimate Time To Crack (assuming 10 billion guesses/sec)
  const combinations = Math.pow(poolSize || 1, length);
  const guessesPerSecond = 10000000000; 
  const seconds = combinations / (2 * guessesPerSecond);

  let timeToCrack = 'Instant';
  if (seconds < 1) timeToCrack = '< 1 second';
  else if (seconds < 60) timeToCrack = `${Math.round(seconds)} seconds`;
  else if (seconds < 3600) timeToCrack = `${Math.round(seconds / 60)} minutes`;
  else if (seconds < 86400) timeToCrack = `${Math.round(seconds / 3600)} hours`;
  else if (seconds < 2592000) timeToCrack = `${Math.round(seconds / 86400)} days`;
  else if (seconds < 31536000) timeToCrack = `${Math.round(seconds / 2592000)} months`;
  else if (seconds < 3153600000) timeToCrack = `${Math.round(seconds / 31536000)} years`;
  else if (seconds < 315360000000) timeToCrack = `${Math.round(seconds / 3153600000)} centuries`;
  else timeToCrack = '300+ Trillion Years';

  const suggestions = [];
  if (length < 12) suggestions.push('Increase length to at least 12-16 characters.');
  if (!hasUppercase) suggestions.push('Add uppercase letters (A-Z).');
  if (!hasLowercase) suggestions.push('Add lowercase letters (a-z).');
  if (!hasNumbers) suggestions.push('Include numbers (0-9).');
  if (!hasSymbols) suggestions.push('Include special symbols (!@#$%^&*).');
  if (hasRepeated) suggestions.push('Avoid repeating identical characters consecutively.');
  if (hasSequential) suggestions.push('Avoid sequential numbers or simple alphabet runs.');
  if (isCommon) suggestions.push('WARNING: This password is in common leak dictionaries!');

  if (suggestions.length === 0) {
    suggestions.push('Excellent! This password is highly resilient against brute-force attacks.');
  }

  return {
    score,
    strength,
    entropyBits: entropy,
    timeToCrack,
    length,
    checks: {
      length: length >= 12,
      hasUppercase,
      hasLowercase,
      hasNumbers,
      hasSymbols,
      noDictionaryWords: !isCommon,
      noRepeatedChars: !hasRepeated,
      noSequentialNums: !hasSequential
    },
    suggestions
  };
}

function generateStrongPassword(length = 16) {
  const uppers = 'ABCDEFGHJKLMNPQRSTUVWXYZ';
  const lowers = 'abcdefghijkmnopqrstuvwxyz';
  const numbers = '23456789';
  const symbols = '!@#$%^&*()_+-=[]{}|;:,.<>?';

  const all = uppers + lowers + numbers + symbols;
  let pwd = '';
  pwd += uppers[Math.floor(Math.random() * uppers.length)];
  pwd += lowers[Math.floor(Math.random() * lowers.length)];
  pwd += numbers[Math.floor(Math.random() * numbers.length)];
  pwd += symbols[Math.floor(Math.random() * symbols.length)];

  for (let i = 4; i < length; i++) {
    pwd += all[Math.floor(Math.random() * all.length)];
  }

  // Shuffle password
  return pwd.split('').sort(() => 0.5 - Math.random()).join('');
}

module.exports = {
  analyzePassword,
  generateStrongPassword
};
