const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const User = require('../models/User');
const Log = require('../models/Log');
const sendEmail = require('../utils/sendEmail');
const sendSMS = require('../utils/sendSMS');

const generateToken = (user) => {
  const secret = process.env.JWT_SECRET;
  if (!secret) {
    throw new Error('JWT_SECRET environment variable is required');
  }
  return jwt.sign(
    { id: user._id, username: user.username, email: user.email || null, role: user.role },
    secret,
    { expiresIn: '24h' }
  );
};

// Helper: Generate cryptographically secure 6-digit OTP
const generateOTP = () => {
  // crypto.randomInt gives a uniformly distributed cryptographic integer
  return String(crypto.randomInt(100000, 999999));
};

// ============================================================
// EMAIL REGISTRATION (EXISTING — UNCHANGED)
// ============================================================

// @desc    Register new user (email method)
// @route   POST /api/auth/register
exports.register = async (req, res, next) => {
  try {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
      return res.status(400).json({ success: false, error: 'Please provide all required fields.' });
    }

    let user;
    try {
      const existingUser = await User.findOne({ email });
      if (existingUser) {
        if (existingUser.isVerified) {
          return res.status(400).json({ success: false, error: 'User with this email already exists.' });
        }
        // Stale unverified account — delete it so user can register cleanly
        await User.deleteOne({ _id: existingUser._id });
      }

      const otp = generateOTP();
      const salt = await bcrypt.genSalt(10);
      const hashedOTP = await bcrypt.hash(otp, salt);

      user = await User.create({
        username,
        email,
        password,
        role: 'user',
        registrationMethod: 'email',
        isVerified: false,
        verificationOTP: hashedOTP,
        verificationOTPExpire: Date.now() + 10 * 60 * 1000, // 10 minutes
        otpLastSentAt: new Date()
      });

      // Send OTP via Email
      const message = `Your CyberShield Security Gateway OTP is: ${otp}\n\nIt is valid for 10 minutes.`;
      try {
        await sendEmail({
          email: user.email,
          subject: 'CyberShield Account Verification OTP',
          message
        });
      } catch (err) {
        console.error('[SMTP Error] Email delivery failed:', err.message || err);
        await User.findByIdAndDelete(user._id);
        return res.status(500).json({ success: false, error: 'Unable to send verification code. Please try again.' });
      }

    } catch (dbErr) {
      return res.status(503).json({ success: false, error: 'Database unavailable. Please try again later.' });
    }

    // Audit Log
    try {
      await Log.create({
        username: user.username,
        action: 'USER_REGISTER',
        details: `New account registered (unverified) via email: ${user.email}`,
        status: 'SUCCESS'
      });
    } catch (e) {}

    res.status(201).json({
      success: true,
      message: 'Verification code sent successfully to your email.'
    });
  } catch (err) {
    next(err);
  }
};

// @desc    Verify Email OTP
// @route   POST /api/auth/verify-otp
exports.verifyOTP = async (req, res, next) => {
  try {
    const { email, otp } = req.body;
    if (!email || !otp) {
      return res.status(400).json({ success: false, error: 'Please provide email and OTP.' });
    }

    const user = await User.findOne({ email }).select('+verificationOTP +verificationOTPExpire');
    if (!user) return res.status(400).json({ success: false, error: 'Invalid user.' });

    if (user.isVerified) {
      return res.status(400).json({ success: false, error: 'Account is already verified.' });
    }

    if (user.otpAttempts >= 5) {
      return res.status(400).json({ success: false, error: 'Too many attempts. Please try again later.' });
    }

    if (!user.verificationOTPExpire || user.verificationOTPExpire < Date.now()) {
      return res.status(400).json({ success: false, error: 'Verification code expired. Please request a new code.' });
    }

    const isMatch = await bcrypt.compare(otp, user.verificationOTP);
    if (!isMatch) {
      user.otpAttempts += 1;
      await user.save();
      return res.status(400).json({ success: false, error: 'Invalid verification code.' });
    }

    user.isVerified = true;
    user.verificationOTP = undefined;
    user.verificationOTPExpire = undefined;
    user.otpAttempts = 0;
    await user.save();

    const token = generateToken(user);
    res.status(200).json({
      success: true,
      token,
      user: { id: user._id, username: user.username, email: user.email, role: user.role }
    });

  } catch (err) {
    next(err);
  }
};

// @desc    Resend Email OTP
// @route   POST /api/auth/resend-otp
exports.resendOTP = async (req, res, next) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ success: false, error: 'Please provide an email.' });

    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ success: false, error: 'User not found.' });
    if (user.isVerified) return res.status(400).json({ success: false, error: 'Account already verified.' });

    // 60-second resend cooldown
    if (user.otpLastSentAt && (Date.now() - new Date(user.otpLastSentAt).getTime()) < 60 * 1000) {
      const waitSec = Math.ceil((60 * 1000 - (Date.now() - new Date(user.otpLastSentAt).getTime())) / 1000);
      return res.status(429).json({ success: false, error: `Please wait ${waitSec} seconds before requesting another code.` });
    }

    const otp = generateOTP();
    const salt = await bcrypt.genSalt(10);
    const hashedOTP = await bcrypt.hash(otp, salt);

    user.verificationOTP = hashedOTP;
    user.verificationOTPExpire = Date.now() + 10 * 60 * 1000;
    user.otpAttempts = 0;
    user.otpLastSentAt = new Date();
    await user.save();

    const message = `Your new CyberShield Security Gateway OTP is: ${otp}\n\nIt is valid for 10 minutes.`;
    try {
      await sendEmail({ email: user.email, subject: 'CyberShield Account Verification OTP', message });
    } catch (err) {
      console.error('[SMTP Error] Resend email delivery failed:', err.message || err);
      return res.status(500).json({ success: false, error: 'Unable to send verification code. Please try again.' });
    }

    res.status(200).json({ success: true, message: 'Verification code sent successfully to your email.' });
  } catch (err) {
    next(err);
  }
};

// ============================================================
// PHONE REGISTRATION (NEW)
// ============================================================

// @desc    Register new user (phone method)
// @route   POST /api/auth/register-phone
exports.registerPhone = async (req, res, next) => {
  try {
    const { username, phoneNumber, password } = req.body;

    if (!username || !phoneNumber || !password) {
      return res.status(400).json({ success: false, error: 'Please provide username, phone number, and password.' });
    }

    let user;
    try {
      // Check for existing verified account with this phone number
      const existingVerified = await User.findOne({ phoneNumber, phoneVerified: true });
      if (existingVerified) {
        return res.status(400).json({ success: false, error: 'This phone number is already registered.' });
      }

      // Delete any stale unverified account with same phone
      const existingUnverified = await User.findOne({ phoneNumber, phoneVerified: false });
      if (existingUnverified) {
        await User.deleteOne({ _id: existingUnverified._id });
      }

      const otp = generateOTP();
      const salt = await bcrypt.genSalt(10);
      const hashedOTP = await bcrypt.hash(otp, salt);

      user = await User.create({
        username,
        phoneNumber,
        password,
        role: 'user',
        registrationMethod: 'phone',
        isVerified: false,   // not email-verified
        phoneVerified: false,
        verificationOTP: hashedOTP,
        verificationOTPExpire: Date.now() + 10 * 60 * 1000, // 10 minutes
        otpLastSentAt: new Date()
      });

      // Send OTP via SMS
      const smsBody = `CyberShield verification code: ${otp}\nThis code expires soon.\nDo not share this code with anyone.`;
      try {
        await sendSMS(phoneNumber, smsBody);
      } catch (smsErr) {
        await User.findByIdAndDelete(user._id);

        if (smsErr.message === 'SMS_NOT_CONFIGURED') {
          return res.status(503).json({
            success: false,
            error: 'SMS service is not configured. Please contact the administrator or use Email verification.'
          });
        }
        return res.status(500).json({ success: false, error: smsErr.message || 'Unable to send OTP right now. Please try again or use Email verification.' });
      }

    } catch (dbErr) {
      if (dbErr.code === 11000) {
        return res.status(400).json({ success: false, error: 'This phone number is already registered.' });
      }
      return res.status(503).json({ success: false, error: 'Database unavailable. Please try again later.' });
    }

    // Audit Log
    try {
      await Log.create({
        username: user.username,
        action: 'USER_REGISTER',
        details: `New account registered (unverified) via phone`,
        status: 'SUCCESS'
      });
    } catch (e) {}

    res.status(201).json({
      success: true,
      message: 'Verification code sent successfully to your mobile number.'
    });
  } catch (err) {
    next(err);
  }
};

// @desc    Verify Phone OTP
// @route   POST /api/auth/verify-phone-otp
exports.verifyPhoneOTP = async (req, res, next) => {
  try {
    const { phoneNumber, otp } = req.body;
    if (!phoneNumber || !otp) {
      return res.status(400).json({ success: false, error: 'Please provide phone number and OTP.' });
    }

    const user = await User.findOne({ phoneNumber }).select('+verificationOTP +verificationOTPExpire');
    if (!user) return res.status(400).json({ success: false, error: 'Invalid phone number.' });

    if (user.phoneVerified) {
      return res.status(400).json({ success: false, error: 'Account is already verified.' });
    }

    if (user.otpAttempts >= 5) {
      return res.status(400).json({ success: false, error: 'Too many attempts. Please request a new code.' });
    }

    if (!user.verificationOTPExpire || user.verificationOTPExpire < Date.now()) {
      return res.status(400).json({ success: false, error: 'Verification code expired. Please request a new code.' });
    }

    const isMatch = await bcrypt.compare(otp, user.verificationOTP);
    if (!isMatch) {
      user.otpAttempts += 1;
      await user.save();
      const remaining = 5 - user.otpAttempts;
      return res.status(400).json({
        success: false,
        error: remaining > 0 ? `Invalid verification code. ${remaining} attempt(s) remaining.` : 'Invalid verification code. Account locked — please request a new code.'
      });
    }

    user.phoneVerified = true;
    user.isVerified = true; // also mark isVerified so general auth checks pass
    user.verificationOTP = undefined;
    user.verificationOTPExpire = undefined;
    user.otpAttempts = 0;
    await user.save();

    const token = generateToken(user);
    res.status(200).json({
      success: true,
      token,
      user: { id: user._id, username: user.username, phoneNumber: user.phoneNumber, role: user.role }
    });

  } catch (err) {
    next(err);
  }
};

// @desc    Resend Phone OTP
// @route   POST /api/auth/resend-phone-otp
exports.resendPhoneOTP = async (req, res, next) => {
  try {
    const { phoneNumber } = req.body;
    if (!phoneNumber) return res.status(400).json({ success: false, error: 'Please provide your phone number.' });

    const user = await User.findOne({ phoneNumber });
    if (!user) return res.status(400).json({ success: false, error: 'Phone number not found.' });
    if (user.phoneVerified) return res.status(400).json({ success: false, error: 'Account already verified.' });

    // 60-second resend cooldown
    if (user.otpLastSentAt && (Date.now() - new Date(user.otpLastSentAt).getTime()) < 60 * 1000) {
      const waitSec = Math.ceil((60 * 1000 - (Date.now() - new Date(user.otpLastSentAt).getTime())) / 1000);
      return res.status(429).json({ success: false, error: `Please wait ${waitSec} seconds before requesting another code.` });
    }

    const otp = generateOTP();
    const salt = await bcrypt.genSalt(10);
    const hashedOTP = await bcrypt.hash(otp, salt);

    user.verificationOTP = hashedOTP;
    user.verificationOTPExpire = Date.now() + 10 * 60 * 1000;
    user.otpAttempts = 0;
    user.otpLastSentAt = new Date();
    await user.save();

    const smsBody = `CyberShield verification code: ${otp}\nThis code expires soon.\nDo not share this code with anyone.`;
    try {
      await sendSMS(phoneNumber, smsBody);
    } catch (smsErr) {
      if (smsErr.message === 'SMS_NOT_CONFIGURED') {
        return res.status(503).json({
          success: false,
          error: 'SMS service is not configured. Please contact the administrator or use Email verification.'
        });
      }
      return res.status(500).json({ success: false, error: smsErr.message || 'Unable to send OTP right now. Please try again or use Email verification.' });
    }

    res.status(200).json({ success: true, message: 'Verification code sent successfully to your mobile number.' });
  } catch (err) {
    next(err);
  }
};

// ============================================================
// LOGIN (UPDATED — supports email OR phone)
// ============================================================

// @desc    Login user
// @route   POST /api/auth/login
exports.login = async (req, res, next) => {
  try {
    const { email, phoneNumber, password } = req.body;

    // Must provide exactly one identifier
    if ((!email && !phoneNumber) || !password) {
      return res.status(400).json({ success: false, error: 'Please enter your email or phone number and password.' });
    }

    let user;
    try {
      if (email) {
        user = await User.findOne({ email }).select('+password');
      } else {
        user = await User.findOne({ phoneNumber }).select('+password');
      }
    } catch (dbErr) {
      return res.status(503).json({ success: false, error: 'Database unavailable. Please try again later.' });
    }

    if (!user) {
      return res.status(401).json({ success: false, error: 'Invalid login credentials.' });
    }

    const isMatch = await user.matchPassword(password);
    if (!isMatch) {
      return res.status(401).json({ success: false, error: 'Invalid login credentials.' });
    }

    // Check verification based on registration method
    if (user.registrationMethod === 'phone') {
      if (!user.phoneVerified) {
        return res.status(403).json({ success: false, error: 'Please verify your mobile number before logging in.', unverified: true, method: 'phone' });
      }
    } else {
      if (!user.isVerified) {
        return res.status(403).json({ success: false, error: 'Please verify your email before logging in.', unverified: true, method: 'email' });
      }
    }

    const token = generateToken(user);

    // Audit Log
    try {
      await Log.create({
        username: user.username,
        action: 'USER_LOGIN',
        details: `User logged in via ${email ? 'email' : 'phone'} from ${req.ip || '127.0.0.1'}`,
        status: 'SUCCESS'
      });
    } catch (e) {}

    res.status(200).json({
      success: true,
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email || null,
        phoneNumber: user.phoneNumber || null,
        role: user.role
      }
    });
  } catch (err) {
    next(err);
  }
};

// ============================================================
// REMAINING ENDPOINTS (UNCHANGED)
// ============================================================

// @desc    Logout user
// @route   POST /api/auth/logout
exports.logout = async (req, res) => {
  res.status(200).json({
    success: true,
    message: 'User logged out successfully.'
  });
};

// @desc    Get Current Logged User
// @route   GET /api/auth/me
exports.getMe = async (req, res) => {
  res.status(200).json({
    success: true,
    user: req.user
  });
};

// @desc    Forgot Password Request
// @route   POST /api/auth/forgot-password
exports.forgotPassword = async (req, res, next) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email });
    if (!user) {
      // Return 200 even if user doesn't exist for security reasons
      return res.status(200).json({ success: true, message: `Password reset verification token sent to ${email || 'your email'}.` });
    }

    const resetToken = crypto.randomBytes(20).toString('hex');
    user.resetPasswordToken = crypto.createHash('sha256').update(resetToken).digest('hex');
    user.resetPasswordExpire = Date.now() + 10 * 60 * 1000;
    await user.save();

    const message = `Your password reset token is: \n\n ${resetToken}\n\nIf you did not request this, please ignore this email.`;
    try {
      await sendEmail({ email: user.email, subject: 'CyberShield Password Reset Token', message });
    } catch (err) {}

    res.status(200).json({ success: true, message: `Password reset verification token sent to ${email}.` });
  } catch (err) {
    next(err);
  }
};

// @desc    Reset Password
// @route   POST /api/auth/reset-password
exports.resetPassword = async (req, res, next) => {
  try {
    const { resetToken, newPassword } = req.body;
    const resetPasswordToken = crypto.createHash('sha256').update(resetToken).digest('hex');

    const user = await User.findOne({
      resetPasswordToken,
      resetPasswordExpire: { $gt: Date.now() }
    });

    if (!user) {
      return res.status(400).json({ success: false, error: 'Invalid or expired reset token' });
    }

    user.password = newPassword;
    user.resetPasswordToken = undefined;
    user.resetPasswordExpire = undefined;
    user.passwordChangedAt = Date.now();
    await user.save();

    res.status(200).json({ success: true, message: 'Password successfully updated. You may now login.' });
  } catch (err) {
    next(err);
  }
};

// @desc    Production Email Diagnostic Endpoint
// @route   POST /api/auth/test-email
exports.testEmail = async (req, res, next) => {
  try {
    const { targetEmail } = req.body;
    if (!targetEmail) {
      return res.status(400).json({ success: false, error: 'Please provide targetEmail' });
    }

    const recipientDomain = targetEmail.split('@')[1];
    const message = `CyberShield Diagnostic Email Test\nRecipient Domain: ${recipientDomain}\nTime: ${new Date().toISOString()}`;

    const result = await sendEmail({
      email: targetEmail,
      subject: 'CyberShield Production Email Diagnostic',
      message
    });

    res.status(200).json({
      success: true,
      message: `Diagnostic email dispatched to ${targetEmail}`,
      diagnostic: {
        recipientDomain,
        provider: result?.provider || 'Unknown',
        sendResult: result?.status || 'SUCCESS',
        responseCode: result?.responseCode || 200,
        providerData: result?.data || {}
      }
    });
  } catch (err) {
    res.status(500).json({
      success: false,
      error: 'Email diagnostic failed',
      providerErrorMessage: err.message
    });
  }
};
