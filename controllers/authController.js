const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const User = require('../models/User');
const PendingRegistration = require('../models/PendingRegistration');
const Log = require('../models/Log');
const sendEmail = require('../utils/sendEmail');
const sendSMS = require('../utils/sendSMS');
const { normalizePhoneNumber } = require('../utils/phoneNormalizer');
const { verifyGoogleToken } = require('../utils/googleAuth');

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
  return String(crypto.randomInt(100000, 999999));
};

// ============================================================
// EMAIL REGISTRATION (TRANSACTIONAL - PENDING STORAGE)
// ============================================================

// @desc    Initiate Email Registration (Send OTP to Pending Registration)
// @route   POST /api/auth/register
exports.register = async (req, res, next) => {
  try {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
      return res.status(400).json({ success: false, error: 'Please provide all required fields.' });
    }

    const cleanEmail = email.trim().toLowerCase();

    // 1. Check if email or username is already registered in permanent User collection
    const existingEmailUser = await User.findOne({ email: cleanEmail, isVerified: true });
    if (existingEmailUser) {
      return res.status(400).json({ success: false, error: 'User with this email already exists.' });
    }

    const existingUsernameUser = await User.findOne({ username: { $regex: new RegExp(`^${username.trim()}$`, 'i') } });
    if (existingUsernameUser && (existingUsernameUser.isVerified || existingUsernameUser.phoneVerified)) {
      return res.status(400).json({ success: false, error: 'Username is already taken. Please choose a different username.' });
    }

    // 2. Remove any previous pending registration for this email/username
    await PendingRegistration.deleteMany({
      $or: [
        { email: cleanEmail },
        { username: { $regex: new RegExp(`^${username.trim()}$`, 'i') } }
      ]
    });

    const otp = generateOTP();
    const salt = await bcrypt.genSalt(10);
    const hashedOTP = await bcrypt.hash(otp, salt);
    const hashedPassword = await bcrypt.hash(password, salt);

    // 3. Create TEMPORARY pending registration record only (NO document in User collection)
    const pending = await PendingRegistration.create({
      username: username.trim(),
      email: cleanEmail,
      password: hashedPassword,
      registrationMethod: 'email',
      verificationOTP: hashedOTP,
      verificationOTPExpire: Date.now() + 10 * 60 * 1000, // 10 minutes
      otpLastSentAt: new Date()
    });

    // 4. Send OTP via Email
    const message = `Your CyberShield Security Gateway OTP is: ${otp}\n\nIt is valid for 10 minutes. Do not share.`;
    try {
      await sendEmail({
        email: pending.email,
        subject: 'CyberShield Account Verification OTP',
        message
      });
    } catch (err) {
      console.error('[SMTP Error] Email delivery failed:', err.message || err);
      await PendingRegistration.findByIdAndDelete(pending._id);
      return res.status(500).json({ success: false, error: 'Unable to send verification code. Please try again.' });
    }

    res.status(201).json({
      success: true,
      message: 'Verification code sent successfully to your email.'
    });
  } catch (err) {
    next(err);
  }
};

// @desc    Verify Email OTP & Create Permanent Account
// @route   POST /api/auth/verify-otp
exports.verifyOTP = async (req, res, next) => {
  try {
    const { email, otp } = req.body;
    if (!email || !otp) {
      return res.status(400).json({ success: false, error: 'Please provide email and OTP.' });
    }

    const cleanEmail = email.trim().toLowerCase();

    // Look up in PendingRegistration collection
    const pending = await PendingRegistration.findOne({ email: cleanEmail, registrationMethod: 'email' });
    if (!pending) {
      // Check if already verified in User collection
      const verifiedUser = await User.findOne({ email: cleanEmail, isVerified: true });
      if (verifiedUser) {
        return res.status(400).json({ success: false, error: 'Account is already verified. Please log in.' });
      }
      return res.status(400).json({ success: false, error: 'Registration session expired or invalid. Please request a new OTP.' });
    }

    if (pending.otpAttempts >= 5) {
      await PendingRegistration.findByIdAndDelete(pending._id);
      return res.status(400).json({ success: false, error: 'Too many attempts. Registration expired — please request a new code.' });
    }

    if (!pending.verificationOTPExpire || pending.verificationOTPExpire < Date.now()) {
      return res.status(400).json({ success: false, error: 'Verification code expired. Please request a new code.' });
    }

    const isMatch = await bcrypt.compare(otp, pending.verificationOTP);
    if (!isMatch) {
      pending.otpAttempts += 1;
      await pending.save();
      const remaining = 5 - pending.otpAttempts;
      return res.status(400).json({
        success: false,
        error: remaining > 0 ? `Invalid verification code. ${remaining} attempt(s) remaining.` : 'Invalid verification code. Please request a new code.'
      });
    }

    // ONLY NOW: Create permanent User in User collection
    const user = await User.create({
      username: pending.username,
      email: pending.email,
      password: pending.password, // already hashed
      role: 'user',
      registrationMethod: 'email',
      isVerified: true
    });

    // Delete pending registration record
    await PendingRegistration.findByIdAndDelete(pending._id);

    // Audit Log
    try {
      await Log.create({
        username: user.username,
        action: 'USER_REGISTER',
        details: `Account registered & verified via email: ${user.email}`,
        status: 'SUCCESS'
      });
    } catch (e) {}

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

    const cleanEmail = email.trim().toLowerCase();

    const pending = await PendingRegistration.findOne({ email: cleanEmail, registrationMethod: 'email' });
    if (!pending) {
      const verified = await User.findOne({ email: cleanEmail, isVerified: true });
      if (verified) return res.status(400).json({ success: false, error: 'Account is already verified. Please log in.' });
      return res.status(400).json({ success: false, error: 'Registration session expired. Please start registration again.' });
    }

    // 60-second resend cooldown
    if (pending.otpLastSentAt && (Date.now() - new Date(pending.otpLastSentAt).getTime()) < 60 * 1000) {
      const waitSec = Math.ceil((60 * 1000 - (Date.now() - new Date(pending.otpLastSentAt).getTime())) / 1000);
      return res.status(429).json({ success: false, error: `Please wait ${waitSec} seconds before requesting another code.` });
    }

    const otp = generateOTP();
    const salt = await bcrypt.genSalt(10);
    const hashedOTP = await bcrypt.hash(otp, salt);

    pending.verificationOTP = hashedOTP;
    pending.verificationOTPExpire = Date.now() + 10 * 60 * 1000;
    pending.otpAttempts = 0;
    pending.otpLastSentAt = new Date();
    await pending.save();

    const message = `Your CyberShield Security Gateway OTP is: ${otp}\n\nIt is valid for 10 minutes. Do not share.`;
    try {
      await sendEmail({
        email: pending.email,
        subject: 'CyberShield Account Verification OTP',
        message
      });
    } catch (err) {
      return res.status(500).json({ success: false, error: 'Unable to send verification code. Please try again.' });
    }

    res.status(200).json({ success: true, message: 'Verification code sent successfully to your email.' });
  } catch (err) {
    next(err);
  }
};

// ============================================================
// MOBILE REGISTRATION (TRANSACTIONAL - PENDING STORAGE)
// ============================================================

// @desc    Initiate Mobile Registration (Send OTP to Pending Registration)
// @route   POST /api/auth/register-phone
exports.registerPhone = async (req, res, next) => {
  try {
    const { username, password } = req.body;
    let { phoneNumber } = req.body;

    if (!username || !phoneNumber || !password) {
      return res.status(400).json({ success: false, error: 'Please provide username, phone number, and password.' });
    }

    try {
      phoneNumber = normalizePhoneNumber(phoneNumber, 'IN');
    } catch (normErr) {
      return res.status(400).json({ success: false, error: normErr.message });
    }

    // 1. Check if phone or username is already registered in permanent User collection
    const existingPhoneUser = await User.findOne({ phoneNumber, phoneVerified: true });
    if (existingPhoneUser) {
      return res.status(400).json({ success: false, error: 'This phone number is already registered.' });
    }

    const existingUsernameUser = await User.findOne({ username: { $regex: new RegExp(`^${username.trim()}$`, 'i') } });
    if (existingUsernameUser && (existingUsernameUser.isVerified || existingUsernameUser.phoneVerified)) {
      return res.status(400).json({ success: false, error: 'Username is already taken. Please choose a different username.' });
    }

    // 2. Remove any previous pending registration for this phone/username
    await PendingRegistration.deleteMany({
      $or: [
        { phoneNumber },
        { username: { $regex: new RegExp(`^${username.trim()}$`, 'i') } }
      ]
    });

    const otp = generateOTP();
    const salt = await bcrypt.genSalt(10);
    const hashedOTP = await bcrypt.hash(otp, salt);
    const hashedPassword = await bcrypt.hash(password, salt);

    // 3. Create TEMPORARY pending registration record only (NO document in User collection)
    const pending = await PendingRegistration.create({
      username: username.trim(),
      phoneNumber,
      password: hashedPassword,
      registrationMethod: 'phone',
      verificationOTP: hashedOTP,
      verificationOTPExpire: Date.now() + 10 * 60 * 1000, // 10 minutes
      otpLastSentAt: new Date()
    });

    // Send OTP via SMS (concise format to comply with carrier DLT SMS rules)
    const smsBody = `CyberShield code: ${otp}`;
    try {
      const smsResult = await sendSMS(phoneNumber, smsBody);
      pending.smsBatchId = smsResult.smsBatchId || null;
      pending.smsStatus = smsResult.status || 'SENT';
      await pending.save();
    } catch (smsErr) {
      await PendingRegistration.findByIdAndDelete(pending._id);

      if (smsErr.message === 'SMS_NOT_CONFIGURED') {
        return res.status(503).json({
          success: false,
          error: 'SMS service is not configured. Please contact administrator or use Email verification.'
        });
      }
      return res.status(500).json({ success: false, error: smsErr.message || 'Unable to send verification code. Please try again.' });
    }

    res.status(201).json({
      success: true,
      message: 'Verification code sent successfully to your mobile number.',
      phoneNumber
    });
  } catch (err) {
    next(err);
  }
};

// @desc    Verify Phone OTP & Create Permanent Account
// @route   POST /api/auth/verify-phone-otp
exports.verifyPhoneOTP = async (req, res, next) => {
  try {
    let { phoneNumber } = req.body;
    const { otp } = req.body;
    if (!phoneNumber || !otp) {
      return res.status(400).json({ success: false, error: 'Please provide phone number and OTP.' });
    }

    try {
      phoneNumber = normalizePhoneNumber(phoneNumber, 'IN');
    } catch (e) {}

    // Look up in PendingRegistration collection
    const pending = await PendingRegistration.findOne({ phoneNumber, registrationMethod: 'phone' });
    if (!pending) {
      const verifiedUser = await User.findOne({ phoneNumber, phoneVerified: true });
      if (verifiedUser) {
        return res.status(400).json({ success: false, error: 'Account is already verified. Please log in.' });
      }
      return res.status(400).json({ success: false, error: 'Registration session expired or invalid. Please request a new OTP.' });
    }

    if (pending.otpAttempts >= 5) {
      await PendingRegistration.findByIdAndDelete(pending._id);
      return res.status(400).json({ success: false, error: 'Too many attempts. Registration expired — please request a new code.' });
    }

    if (!pending.verificationOTPExpire || pending.verificationOTPExpire < Date.now()) {
      return res.status(400).json({ success: false, error: 'Verification code expired. Please request a new code.' });
    }

    const isMatch = await bcrypt.compare(otp, pending.verificationOTP);
    if (!isMatch) {
      pending.otpAttempts += 1;
      await pending.save();
      const remaining = 5 - pending.otpAttempts;
      return res.status(400).json({
        success: false,
        error: remaining > 0 ? `Invalid verification code. ${remaining} attempt(s) remaining.` : 'Invalid verification code. Please request a new code.'
      });
    }

    // ONLY NOW: Create permanent User in User collection
    const user = await User.create({
      username: pending.username,
      phoneNumber: pending.phoneNumber,
      password: pending.password, // already hashed
      role: 'user',
      registrationMethod: 'phone',
      isVerified: true,
      phoneVerified: true
    });

    // Delete pending registration record
    await PendingRegistration.findByIdAndDelete(pending._id);

    // Audit Log
    try {
      await Log.create({
        username: user.username,
        action: 'USER_REGISTER',
        details: `Account registered & verified via phone: ${user.phoneNumber}`,
        status: 'SUCCESS'
      });
    } catch (e) {}

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
    let { phoneNumber } = req.body;
    if (!phoneNumber) return res.status(400).json({ success: false, error: 'Please provide your phone number.' });

    try {
      phoneNumber = normalizePhoneNumber(phoneNumber, 'IN');
    } catch (e) {}

    const pending = await PendingRegistration.findOne({ phoneNumber, registrationMethod: 'phone' });
    if (!pending) {
      const verified = await User.findOne({ phoneNumber, phoneVerified: true });
      if (verified) return res.status(400).json({ success: false, error: 'Account already verified. Please log in.' });
      return res.status(400).json({ success: false, error: 'Registration session expired. Please start registration again.' });
    }

    // 60-second resend cooldown
    if (pending.otpLastSentAt && (Date.now() - new Date(pending.otpLastSentAt).getTime()) < 60 * 1000) {
      const waitSec = Math.ceil((60 * 1000 - (Date.now() - new Date(pending.otpLastSentAt).getTime())) / 1000);
      return res.status(429).json({ success: false, error: `Please wait ${waitSec} seconds before requesting another code.` });
    }

    const otp = generateOTP();
    const salt = await bcrypt.genSalt(10);
    const hashedOTP = await bcrypt.hash(otp, salt);

    pending.verificationOTP = hashedOTP;
    pending.verificationOTPExpire = Date.now() + 10 * 60 * 1000;
    pending.otpAttempts = 0;
    pending.otpLastSentAt = new Date();
    await pending.save();

    const smsBody = `CyberShield code: ${otp}`;
    try {
      const smsResult = await sendSMS(phoneNumber, smsBody);
      pending.smsBatchId = smsResult.smsBatchId || null;
      pending.smsStatus = smsResult.status || 'SENT';
      await pending.save();
    } catch (smsErr) {
      return res.status(500).json({ success: false, error: smsErr.message || 'Unable to send OTP right now. Please try again.' });
    }

    res.status(200).json({ success: true, message: 'Verification code sent successfully to your mobile number.' });
  } catch (err) {
    next(err);
  }
};

// ============================================================
// AUTHENTICATION (LOGIN & LOGOUT)
// ============================================================

// @desc    Login user (Email or Phone)
// @route   POST /api/auth/login
exports.login = async (req, res, next) => {
  try {
    const { email, phoneNumber, password } = req.body;

    if ((!email && !phoneNumber) || !password) {
      return res.status(400).json({ success: false, error: 'Please enter your email or phone number and password.' });
    }

    let user;
    try {
      if (email) {
        const cleanEmail = email.trim().toLowerCase();
        user = await User.findOne({ email: cleanEmail, isVerified: true }).select('+password');
      } else {
        let canonicalPhone = phoneNumber;
        try {
          canonicalPhone = normalizePhoneNumber(phoneNumber, 'IN');
        } catch (e) {}
        user = await User.findOne({ phoneNumber: canonicalPhone, phoneVerified: true }).select('+password');
      }
    } catch (dbErr) {
      return res.status(503).json({ success: false, error: 'Database unavailable. Please try again later.' });
    }

    if (!user) {
      return res.status(401).json({ success: false, error: 'Invalid credentials or account not verified.' });
    }

    const isMatch = await user.matchPassword(password);
    if (!isMatch) {
      return res.status(401).json({ success: false, error: 'Invalid credentials.' });
    }

    const token = generateToken(user);

    // Audit Log
    try {
      await Log.create({
        username: user.username,
        action: 'USER_LOGIN',
        details: `Successful login via ${email ? 'email' : 'phone'}`,
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

// @desc    Logout user
// @route   POST /api/auth/logout
exports.logout = async (req, res) => {
  res.status(200).json({ success: true, message: 'Logged out successfully' });
};

// @desc    Get current user profile
// @route   GET /api/auth/me
exports.getMe = async (req, res, next) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ success: false, error: 'User not found' });
    res.status(200).json({ success: true, data: user });
  } catch (err) {
    next(err);
  }
};

// ============================================================
// FORGOT & RESET PASSWORD (SECURE EMAIL & PHONE RECOVERY)
// ============================================================

// @desc    Initiate Password Reset (Generates Reset OTP)
// @route   POST /api/auth/forgot-password
exports.forgotPassword = async (req, res, next) => {
  try {
    const { identifier } = req.body; // Email or Phone number
    const genericResponse = {
      success: true,
      message: 'If an account exists with these details, a password reset code has been sent.'
    };

    if (!identifier || typeof identifier !== 'string' || !identifier.trim()) {
      return res.status(400).json({ success: false, error: 'Please provide your email address or phone number.' });
    }

    const input = identifier.trim();
    let user = null;

    // Check if input is email or phone
    if (input.includes('@')) {
      user = await User.findOne({ email: input.toLowerCase(), isVerified: true });
    } else {
      try {
        const canonical = normalizePhoneNumber(input, 'IN');
        user = await User.findOne({ phoneNumber: canonical, phoneVerified: true });
      } catch (_) {}
    }

    if (!user) {
      // Return generic response to prevent account enumeration
      return res.status(200).json(genericResponse);
    }

    const otp = generateOTP();
    const salt = await bcrypt.genSalt(10);
    const hashedOTP = await bcrypt.hash(otp, salt);

    user.resetPasswordToken = hashedOTP;
    user.resetPasswordExpire = Date.now() + 10 * 60 * 1000; // 10 mins
    await user.save();

    if (user.email) {
      try {
        await sendEmail({
          email: user.email,
          subject: 'CyberShield Password Reset Code',
          message: `CyberShield Password Reset Code: ${otp}. Valid for 10 minutes. Do not share.`
        });
      } catch (e) {
        console.error('[Forgot Password Email Error]:', e.message);
      }
    } else if (user.phoneNumber) {
      try {
        await sendSMS(user.phoneNumber, `CyberShield reset code: ${otp}`);
      } catch (e) {
        console.error('[Forgot Password SMS Error]:', e.message);
      }
    }

    return res.status(200).json(genericResponse);

  } catch (err) {
    next(err);
  }
};

// @desc    Reset Password with Verified OTP
// @route   POST /api/auth/reset-password
exports.resetPassword = async (req, res, next) => {
  try {
    const { identifier, otp, newPassword } = req.body;

    if (!identifier || !otp || !newPassword) {
      return res.status(400).json({ success: false, error: 'Please provide identifier, reset code, and new password.' });
    }

    if (newPassword.length < 8) {
      return res.status(400).json({ success: false, error: 'Password must be at least 8 characters long.' });
    }

    const input = identifier.trim();
    let user = null;

    if (input.includes('@')) {
      user = await User.findOne({ email: input.toLowerCase(), isVerified: true }).select('+resetPasswordToken +resetPasswordExpire');
    } else {
      try {
        const canonical = normalizePhoneNumber(input, 'IN');
        user = await User.findOne({ phoneNumber: canonical, phoneVerified: true }).select('+resetPasswordToken +resetPasswordExpire');
      } catch (_) {}
    }

    if (!user || !user.resetPasswordToken || !user.resetPasswordExpire) {
      return res.status(400).json({ success: false, error: 'Invalid or expired password reset code.' });
    }

    if (user.resetPasswordExpire < Date.now()) {
      user.resetPasswordToken = undefined;
      user.resetPasswordExpire = undefined;
      await user.save();
      return res.status(400).json({ success: false, error: 'Password reset code has expired. Please request a new code.' });
    }

    const isMatch = await bcrypt.compare(otp, user.resetPasswordToken);
    if (!isMatch) {
      return res.status(400).json({ success: false, error: 'Invalid password reset code.' });
    }

    // Update password
    user.password = newPassword;
    user.resetPasswordToken = undefined;
    user.resetPasswordExpire = undefined;
    user.passwordChangedAt = new Date();
    await user.save();

    // Audit Log
    try {
      await Log.create({
        username: user.username,
        action: 'PASSWORD_RESET',
        details: 'Password successfully updated via OTP reset',
        status: 'SUCCESS'
      });
    } catch (e) {}

    res.status(200).json({
      success: true,
      message: 'Password updated successfully. You can now log in with your new password.'
    });

  } catch (err) {
    next(err);
  }
};

// ============================================================
// DIAGNOSTICS (TEST ENDPOINTS)
// ============================================================

exports.testEmail = async (req, res) => {
  try {
    const { targetEmail } = req.body;
    if (!targetEmail) return res.status(400).json({ success: false, error: 'Target email required' });
    await sendEmail({
      email: targetEmail,
      subject: 'CyberShield Test Email',
      message: 'Diagnostic email test.'
    });
    res.status(200).json({ success: true, message: 'Email sent successfully.' });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
};

exports.testSMS = async (req, res) => {
  try {
    let { targetPhone, phoneNumber, message } = req.body;
    const phoneInput = targetPhone || phoneNumber;
    if (!phoneInput) return res.status(400).json({ success: false, error: 'Target phone number required' });

    const canonicalPhone = normalizePhoneNumber(phoneInput, 'IN');
    const result = await sendSMS(canonicalPhone, message || 'CyberShield SMS TEST');

    res.status(200).json({
      success: true,
      diagnostic: {
        messageSent: message || 'CyberShield SMS TEST',
        targetCanonical: canonicalPhone.replace(/\d(?=\d{4})/g, '*'),
        provider: result.provider,
        status: result.status,
        smsBatchId: result.smsBatchId,
        endpointUsed: result.endpointUsed
      }
    });
  } catch (err) {
    res.status(500).json({
      success: false,
      error: err.message || 'SMS Diagnostic Test Failed'
    });
  }
};

// @desc    Google Single Sign-On (SSO) Real Verification Handler
// @route   POST /api/auth/google
exports.googleAuth = async (req, res, next) => {
  try {
    const { credential, id_token, token } = req.body;
    const googleToken = credential || id_token || token;

    if (!googleToken) {
      return res.status(400).json({
        success: false,
        error: 'Google authentication credential is required.'
      });
    }

    // 1. Backend Token Verification using Google Official Library / TokenInfo API
    let verifiedGoogleUser = null;
    try {
      verifiedGoogleUser = await verifyGoogleToken(googleToken);
    } catch (verr) {
      console.error('[Google Verification Failed]:', verr.message);
      return res.status(401).json({
        success: false,
        error: verr.message || 'Google authentication could not be verified.'
      });
    }

    const { googleId, email, name, picture, emailVerified } = verifiedGoogleUser;

    if (!emailVerified || !email) {
      return res.status(400).json({
        success: false,
        error: 'Please use a verified Google account.'
      });
    }

    // 2. Account Lookup & Safe Account Linking
    let user = await User.findOne({ $or: [{ googleId }, { email }] });

    if (user) {
      // Existing User Account Found — Link Google ID securely
      if (!user.googleId) {
        user.googleId = googleId;
      }
      user.isVerified = true;
      if (picture && !user.avatar) {
        user.avatar = picture;
      }
      await user.save();
    } else {
      // Create new permanent verified User document
      const randomPassword = crypto.randomBytes(16).toString('hex');
      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(randomPassword, salt);

      let baseUsername = name.replace(/[^a-zA-Z0-9]/g, '');
      if (baseUsername.length < 3) baseUsername = 'GoogleUser';
      let uniqueUsername = baseUsername;
      let counter = 1;
      while (await User.findOne({ username: uniqueUsername })) {
        uniqueUsername = `${baseUsername}${counter++}`;
      }

      user = await User.create({
        username: uniqueUsername,
        email: email,
        password: hashedPassword,
        googleId: googleId,
        role: 'user',
        registrationMethod: 'google',
        isVerified: true,
        avatar: picture || 'avatar-cyber-1.png'
      });

      try {
        await Log.create({
          username: user.username,
          action: 'USER_REGISTER_GOOGLE',
          details: `Verified Google account created for ${user.email} (ID: ${googleId})`,
          status: 'SUCCESS'
        });
      } catch (e) {}
    }

    // 3. Create Secure Session Token
    const jwtToken = generateToken(user);

    res.status(200).json({
      success: true,
      token: jwtToken,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role,
        avatar: user.avatar
      }
    });

  } catch (err) {
    next(err);
  }
};

