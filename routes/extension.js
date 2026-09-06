/**
 * CyberShield – Chrome Extension API Routes
 * Base path: /api/extension
 */

const express = require('express');
const rateLimit = require('express-rate-limit');
const router = express.Router();
const { checkDomain, saveAlert, reportFalsePositive, extensionScan } = require('../controllers/extensionController');
const { protect, optionalAuth } = require('../middleware/authMiddleware');

// Dedicated rate limiter for extension — stricter than global to prevent API abuse
const extensionLimiter = rateLimit({
  windowMs: 5 * 60 * 1000, // 5 minutes
  max: 30,                  // 30 checks per 5 min per IP
  message: { success: false, error: 'Too many extension checks. Please wait a moment.' },
  standardHeaders: true,
  legacyHeaders: false
});

const reportLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 10,                   // 10 reports per hour per IP
  message: { success: false, error: 'Too many reports from this IP.' }
});

// POST /api/extension/check  — no auth, optional JWT (used if present)
router.post('/check', extensionLimiter, optionalAuth, checkDomain);

// POST /api/extension/alert  — requires auth (saves to user notification center)
router.post('/alert', protect, saveAlert);

// POST /api/extension/report-false-positive  — anonymous allowed
router.post('/report-false-positive', reportLimiter, optionalAuth, reportFalsePositive);

// Legacy route kept for backward compat with old extension builds
router.post('/scan', extensionLimiter, extensionScan);

module.exports = router;
