const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const UserSchema = new mongoose.Schema({
  username: {
    type: String,
    required: [true, 'Please provide a username'],
    trim: true,
    minlength: 3,
    maxlength: 30
  },
  // Email is optional — only required for email-registration method
  email: {
    type: String,
    required: false,
    default: null,
    unique: true,
    sparse: true,
    lowercase: true,
    match: [/^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/, 'Please fill a valid email address']
  },
  // Phone number in E.164 format (e.g. +919876543210) — optional for email registrations
  phoneNumber: {
    type: String,
    required: false,
    default: null,
    unique: true,
    sparse: true
  },
  password: {
    type: String,
    required: [true, 'Please provide a password'],
    minlength: 8,
    select: false
  },
  role: {
    type: String,
    enum: ['user', 'admin'],
    default: 'user'
  },
  avatar: {
    type: String,
    default: 'avatar-cyber-1.png'
  },
  twoFactorEnabled: {
    type: Boolean,
    default: false
  },
  emailNotifications: {
    type: Boolean,
    default: true
  },
  // Google OAuth ID
  googleId: {
    type: String,
    required: false,
    default: null,
    sparse: true
  },
  // Registration method: 'email', 'phone', or 'google'
  registrationMethod: {
    type: String,
    enum: ['email', 'phone', 'google'],
    default: 'email'
  },
  // Email verification (existing flow — unchanged)
  isVerified: {
    type: Boolean,
    default: false
  },
  // Phone verification
  phoneVerified: {
    type: Boolean,
    default: false
  },
  // Shared OTP fields (used by both email and phone OTP flows)
  verificationOTP: {
    type: String,
    select: false
  },
  verificationOTPExpire: Date,
  otpAttempts: {
    type: Number,
    default: 0
  },
  // Timestamp of last OTP send — used for 60-second resend cooldown
  otpLastSentAt: {
    type: Date,
    default: null
  },
  // SMS Gateway Batch Tracking
  smsBatchId: {
    type: String,
    default: null
  },
  smsStatus: {
    type: String,
    enum: ['PENDING', 'QUEUED', 'SENT', 'DELIVERED', 'FAILED', null],
    default: null
  },
  // Password reset
  resetPasswordToken: String,
  resetPasswordExpire: Date,
  passwordChangedAt: Date,
  createdAt: {
    type: Date,
    default: Date.now
  }
});

// Indexes
UserSchema.index({ username: 1 });
UserSchema.index({ role: 1 });
UserSchema.index({ createdAt: -1 });

// Encrypt password using bcrypt before saving
UserSchema.pre('save', async function(next) {
  if (!this.isModified('password')) {
    next();
  }
  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
});

// Match user entered password to hashed password in database
UserSchema.methods.matchPassword = async function(enteredPassword) {
  return await bcrypt.compare(enteredPassword, this.password);
};

module.exports = mongoose.model('User', UserSchema);
