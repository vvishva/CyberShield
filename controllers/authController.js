const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const User = require('../models/User');
const Log = require('../models/Log');
const sendEmail = require('../utils/sendEmail');

const generateToken = (user) => {
  const secret = process.env.JWT_SECRET;
  if (!secret) {
    throw new Error('JWT_SECRET environment variable is required');
  }
  return jwt.sign(
    { id: user._id, username: user.username, email: user.email, role: user.role },
    secret,
    { expiresIn: '24h' }
  );
};

// Helper: Generate OTP
const generateOTP = () => {
  return Math.floor(100000 + Math.random() * 900000).toString();
};

// @desc    Register new user
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
        return res.status(400).json({ success: false, error: 'User with this email already exists.' });
      }

      const otp = generateOTP();
      const salt = await bcrypt.genSalt(10);
      const hashedOTP = await bcrypt.hash(otp, salt);

      user = await User.create({
        username,
        email,
        password,
        role: 'user',
        isVerified: false,
        verificationOTP: hashedOTP,
        verificationOTPExpire: Date.now() + 10 * 60 * 1000 // 10 minutes
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
        console.error('Email failed:', err);
        await User.findByIdAndDelete(user._id);
        return res.status(500).json({ success: false, error: 'Unable to send verification email. Please try again later.' });
      }

    } catch (dbErr) {
      return res.status(503).json({ success: false, error: 'Database unavailable. Please try again later.' });
    }

    // Audit Log
    try {
      await Log.create({
        username: user.username,
        action: 'USER_REGISTER',
        details: `New account registered (unverified): ${user.email}`,
        status: 'SUCCESS'
      });
    } catch (e) {}

    res.status(201).json({
      success: true,
      message: 'Verification code sent to your email.'
    });
  } catch (err) {
    next(err);
  }
};

// @desc    Verify OTP
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

// @desc    Resend OTP
// @route   POST /api/auth/resend-otp
exports.resendOTP = async (req, res, next) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ success: false, error: 'Please provide an email.' });

    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ success: false, error: 'User not found.' });
    if (user.isVerified) return res.status(400).json({ success: false, error: 'Account already verified.' });

    const otp = generateOTP();
    const salt = await bcrypt.genSalt(10);
    const hashedOTP = await bcrypt.hash(otp, salt);

    user.verificationOTP = hashedOTP;
    user.verificationOTPExpire = Date.now() + 10 * 60 * 1000;
    user.otpAttempts = 0;
    await user.save();

    const message = `Your new CyberShield Security Gateway OTP is: ${otp}\n\nIt is valid for 10 minutes.`;
    try {
      await sendEmail({ email: user.email, subject: 'CyberShield Account Verification OTP', message });
    } catch (err) {
      console.error('Email failed:', err);
      return res.status(500).json({ success: false, error: 'Unable to send verification email. Please try again later.' });
    }

    res.status(200).json({ success: true, message: 'Verification code sent to your email.' });
  } catch (err) {
    next(err);
  }
};

// @desc    Login user
// @route   POST /api/auth/login
exports.login = async (req, res, next) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ success: false, error: 'Please enter email and password.' });
    }

    let user;
    try {
      user = await User.findOne({ email }).select('+password');
      if (user) {
        const isMatch = await user.matchPassword(password);
        if (!isMatch) {
          return res.status(401).json({ success: false, error: 'Invalid login credentials.' });
        }
      }
    } catch (dbErr) {
      return res.status(503).json({ success: false, error: 'Database unavailable. Please try again later.' });
    }

    if (!user) {
      return res.status(401).json({ success: false, error: 'Invalid login credentials.' });
    }

    if (!user.isVerified) {
      return res.status(403).json({ success: false, error: 'Please verify your email before logging in.', unverified: true });
    }

    const token = generateToken(user);

    // Audit Log
    try {
      await Log.create({
        username: user.username,
        action: 'USER_LOGIN',
        details: `User logged in from ${req.ip || '127.0.0.1'}`,
        status: 'SUCCESS'
      });
    } catch (e) {}

    res.status(200).json({
      success: true,
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role
      }
    });
  } catch (err) {
    next(err);
  }
};

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
