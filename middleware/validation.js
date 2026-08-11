const { body, param, query, validationResult } = require('express-validator');
const { normalizePhoneNumber } = require('../utils/phoneNormalizer');

const handleValidationErrors = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      error: errors.array()[0].msg,
      details: errors.array().map(e => ({ field: e.path, message: e.msg }))
    });
  }
  next();
};

// Password strength rules (shared)
const passwordRules = body('password')
  .isLength({ min: 8 }).withMessage('Password must be at least 8 characters')
  .matches(/[A-Z]/).withMessage('Password must contain an uppercase letter')
  .matches(/[a-z]/).withMessage('Password must contain a lowercase letter')
  .matches(/[0-9]/).withMessage('Password must contain a number')
  .matches(/[^A-Za-z0-9]/).withMessage('Password must contain a special character');

// Phone number validator & canonical normalizer helper
const normalizeAndValidatePhone = (value, { req, location, path }) => {
  if (!value || typeof value !== 'string' || value.trim() === '') {
    throw new Error('Please enter a valid mobile number.');
  }
  try {
    const canonical = normalizePhoneNumber(value, 'IN');
    // Automatically replace request body field with canonical E.164 (+91XXXXXXXXXX)
    req.body[path] = canonical;
    return true;
  } catch (err) {
    throw new Error('Invalid mobile phone number format. Please enter a valid number (e.g. 9876543210 or +919876543210)');
  }
};

const validators = {
  // ── Email Registration (existing — unchanged) ──────────────────────────────
  register: [
    body('username').trim().isLength({ min: 3, max: 30 }).withMessage('Username must be 3-30 characters'),
    body('email').isEmail().normalizeEmail().withMessage('Valid email is required'),
    passwordRules,
    handleValidationErrors
  ],

  // ── Phone Registration (new) ───────────────────────────────────────────────
  registerPhone: [
    body('username').trim().isLength({ min: 3, max: 30 }).withMessage('Username must be 3-30 characters'),
    body('phoneNumber').trim().custom(normalizeAndValidatePhone),
    passwordRules,
    handleValidationErrors
  ],

  // ── Login (updated — accepts email OR phoneNumber) ─────────────────────────
  login: [
    body().custom((_, { req }) => {
      const hasEmail = req.body.email && req.body.email.trim() !== '';
      const hasPhone = req.body.phoneNumber && req.body.phoneNumber.trim() !== '';
      if (!hasEmail && !hasPhone) {
        throw new Error('Please provide your email address or phone number');
      }
      if (hasEmail && hasPhone) {
        throw new Error('Please provide either email or phone number, not both');
      }
      if (hasPhone) {
        try {
          req.body.phoneNumber = normalizePhoneNumber(req.body.phoneNumber, 'IN');
        } catch (e) {
          throw new Error('Invalid mobile phone number format');
        }
      }
      return true;
    }),
    body('email').optional({ checkFalsy: true }).isEmail().normalizeEmail().withMessage('Valid email is required'),
    body('password').notEmpty().withMessage('Password is required'),
    handleValidationErrors
  ],

  // ── Email OTP verification (existing — unchanged) ──────────────────────────
  verifyOTP: [
    body('email').isEmail().normalizeEmail().withMessage('Valid email is required'),
    body('otp').isString().isLength({ min: 6, max: 6 }).withMessage('OTP must be 6 digits'),
    handleValidationErrors
  ],

  // ── Phone OTP verification (new) ───────────────────────────────────────────
  verifyPhoneOTP: [
    body('phoneNumber').trim().custom(normalizeAndValidatePhone),
    body('otp').isString().isLength({ min: 6, max: 6 }).withMessage('OTP must be 6 digits'),
    handleValidationErrors
  ],

  // ── Resend Email OTP (existing — unchanged) ────────────────────────────────
  resendOTP: [
    body('email').isEmail().normalizeEmail().withMessage('Valid email is required'),
    handleValidationErrors
  ],

  // ── Resend Phone OTP (new) ─────────────────────────────────────────────────
  resendPhoneOTP: [
    body('phoneNumber').trim().custom(normalizeAndValidatePhone),
    handleValidationErrors
  ],

  // ── Scan validators (unchanged) ────────────────────────────────────────────
  scanUrl: [
    body('url').trim().notEmpty().withMessage('URL is required')
      .isURL({ require_protocol: false }).withMessage('Invalid URL format'),
    handleValidationErrors
  ],

  scanWebsite: [
    body('url').trim().notEmpty().withMessage('URL is required')
      .isURL({ require_protocol: false }).withMessage('Invalid URL format'),
    handleValidationErrors
  ],

  scanPassword: [
    body('password').isString().notEmpty().withMessage('Password is required'),
    handleValidationErrors
  ],

  scanIp: [
    body('ip').trim().notEmpty().withMessage('IP address is required')
      .custom(value => {
        const ipv4 = /^(\d{1,3}\.){3}\d{1,3}$/;
        const ipv6 = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;
        if (!ipv4.test(value) && !ipv6.test(value)) {
          throw new Error('Invalid IP address format');
        }
        return true;
      }),
    handleValidationErrors
  ],

  scanHash: [
    body('md5').optional().isLength({ min: 32, max: 32 }).isHexadecimal().withMessage('Invalid MD5 hash'),
    body('sha1').optional().isLength({ min: 40, max: 40 }).isHexadecimal().withMessage('Invalid SHA1 hash'),
    body('sha256').optional().isLength({ min: 64, max: 64 }).isHexadecimal().withMessage('Invalid SHA256 hash'),
    body('fileName').optional().isString().trim(),
    handleValidationErrors
  ],

  // ── User validators (unchanged) ────────────────────────────────────────────
  updateProfile: [
    body('username').optional().trim().isLength({ min: 3, max: 30 }).withMessage('Username must be 3-30 characters'),
    body('avatar').optional().isString(),
    body('twoFactorEnabled').optional().isBoolean(),
    body('emailNotifications').optional().isBoolean(),
    handleValidationErrors
  ],

  // ── Admin validators (unchanged) ───────────────────────────────────────────
  createTip: [
    body('title').trim().isLength({ min: 5, max: 100 }).withMessage('Title must be 5-100 characters'),
    body('category').optional().isIn(['Password Safety', 'Phishing Awareness', 'Email Hygiene', 'Safe Browsing', 'Network Security', 'General Cyber']),
    body('content').trim().isLength({ min: 20 }).withMessage('Content must be at least 20 characters'),
    body('severity').optional().isIn(['INFO', 'IMPORTANT', 'CRITICAL']),
    handleValidationErrors
  ],

  // ── Report validators (unchanged) ──────────────────────────────────────────
  generateReport: [
    body('title').trim().isLength({ min: 5, max: 200 }).withMessage('Title must be 5-200 characters'),
    body('target').trim().notEmpty().withMessage('Target is required'),
    body('scanType').isIn(['url_phishing', 'website_security', 'ip_reputation', 'file_hash', 'password_check']),
    body('riskScore').isInt({ min: 0, max: 100 }).withMessage('Risk score must be 0-100'),
    body('findings').optional().isArray(),
    body('recommendations').optional().isArray(),
    handleValidationErrors
  ],

  // ── Param validators (unchanged) ───────────────────────────────────────────
  mongoId: [
    param('id').isMongoId().withMessage('Invalid ID format'),
    handleValidationErrors
  ]
};

module.exports = validators;