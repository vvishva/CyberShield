const express = require('express');
const router = express.Router();
const {
  register, login, logout, getMe, forgotPassword, resetPassword,
  verifyOTP, resendOTP, testEmail,
  // Phone registration (new)
  registerPhone, verifyPhoneOTP, resendPhoneOTP
} = require('../controllers/authController');
const { protect } = require('../middleware/authMiddleware');
const {
  register: registerValidator,
  login: loginValidator,
  verifyOTP: verifyOTPValidator,
  resendOTP: resendOTPValidator,
  // Phone validators (new)
  registerPhone: registerPhoneValidator,
  verifyPhoneOTP: verifyPhoneOTPValidator,
  resendPhoneOTP: resendPhoneOTPValidator
} = require('../middleware/validation');

// ── Email Registration (existing — unchanged) ─────────────────────────────────
router.post('/register', registerValidator, register);
router.post('/verify-otp', verifyOTPValidator, verifyOTP);
router.post('/resend-otp', resendOTPValidator, resendOTP);

// ── Phone Registration (new) ──────────────────────────────────────────────────
router.post('/register-phone', registerPhoneValidator, registerPhone);
router.post('/verify-phone-otp', verifyPhoneOTPValidator, verifyPhoneOTP);
router.post('/resend-phone-otp', resendPhoneOTPValidator, resendPhoneOTP);

// ── Authentication (shared) ───────────────────────────────────────────────────
router.post('/login', loginValidator, login);
router.post('/logout', logout);
router.get('/me', protect, getMe);
router.post('/forgot-password', forgotPassword);
router.post('/reset-password', resetPassword);
router.post('/test-email', testEmail);

module.exports = router;
