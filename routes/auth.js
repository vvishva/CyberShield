const express = require('express');
const router = express.Router();
const { register, login, logout, getMe, forgotPassword, resetPassword, verifyOTP, resendOTP, testEmail } = require('../controllers/authController');
const { protect } = require('../middleware/authMiddleware');
const { register: registerValidator, login: loginValidator, verifyOTP: verifyOTPValidator, resendOTP: resendOTPValidator } = require('../middleware/validation');

router.post('/register', registerValidator, register);
router.post('/login', loginValidator, login);
router.post('/logout', logout);
router.get('/me', protect, getMe);
router.post('/forgot-password', forgotPassword);
router.post('/reset-password', resetPassword);
router.post('/verify-otp', verifyOTPValidator, verifyOTP);
router.post('/resend-otp', resendOTPValidator, resendOTP);
router.post('/test-email', testEmail);

module.exports = router;
