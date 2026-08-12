const express = require('express');
const router = express.Router();
const rateLimit = require('express-rate-limit');
const { protect } = require('../middleware/authMiddleware');
const {
  chat,
  getBriefing,
  explainScore,
  explainScan,
  explainVulnerability,
  investigate,
  generateReport
} = require('../controllers/aiController');

// Rate Limiter for AI endpoints to prevent API key exhaustion
const aiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 60, // 60 requests per 15 minutes
  message: {
    success: false,
    error: 'AI Copilot rate limit exceeded. Please wait a few minutes before sending more security requests.'
  },
  standardHeaders: true,
  legacyHeaders: false
});

// Protect all AI Copilot routes with JWT authentication & rate limiting
router.use(protect);
router.use(aiLimiter);

router.post('/chat', chat);
router.get('/briefing', getBriefing);
router.post('/explain-score', explainScore);
router.post('/explain-scan', explainScan);
router.post('/explain-vulnerability', explainVulnerability);
router.post('/investigate', investigate);
router.post('/generate-report', generateReport);

module.exports = router;
