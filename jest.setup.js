// Jest setup file
process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = 'test_secret_key_for_testing_only_32chars!!';
process.env.MONGO_URI = 'mongodb://localhost:27017/cybershield_test';
process.env.PYTHON_AI_URL = 'http://localhost:5001/predict-url';

// Mock console.error to reduce noise in tests
const originalError = console.error;
console.error = (...args) => {
  if (args[0]?.includes?.('[CyberShield API Error]')) return;
  originalError.apply(console, args);
};

// Global test timeout
jest.setTimeout(10000);