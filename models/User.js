const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

const UserSchema = new mongoose.Schema({
  username: {
    type: String,
    required: [true, 'Please provide a username'],
    trim: true,
    minlength: 3,
    maxlength: 30
  },
  fullName: {
    type: String,
    trim: true,
    default: ''
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
  country: {
    type: String,
    default: 'United States'
  },
  timezone: {
    type: String,
    default: 'UTC-05:00 (EST)'
  },
  language: {
    type: String,
    default: 'English (US)'
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
  status: {
    type: String,
    enum: ['active', 'disabled', 'suspended'],
    default: 'active'
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
  // Email verification
  isVerified: {
    type: Boolean,
    default: false
  },
  // Phone verification
  phoneVerified: {
    type: Boolean,
    default: false
  },
  // Shared OTP fields
  verificationOTP: {
    type: String,
    select: false
  },
  verificationOTPExpire: Date,
  otpAttempts: {
    type: Number,
    default: 0
  },
  otpLastSentAt: {
    type: Date,
    default: null
  },
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
  passwordChangedAt: {
    type: Date,
    default: Date.now
  },
  lastLoginAt: {
    type: Date,
    default: Date.now
  },
  lastLoginIp: {
    type: String,
    default: '127.0.0.1'
  },
  lastLoginDevice: {
    type: String,
    default: 'Windows PC (Chrome)'
  },
  // Active Sessions
  sessions: [{
    sessionId: {
      type: String,
      default: () => crypto.randomBytes(16).toString('hex')
    },
    device: { type: String, default: 'Desktop Browser' },
    os: { type: String, default: 'Windows 11' },
    browser: { type: String, default: 'Chrome' },
    ip: { type: String, default: '127.0.0.1' },
    location: { type: String, default: 'Local Network' },
    lastActive: { type: Date, default: Date.now },
    createdAt: { type: Date, default: Date.now },
    current: { type: Boolean, default: false }
  }],
  // Security Activity Audit Trail
  securityActivity: [{
    event: { type: String, required: true },
    ip: { type: String, default: '127.0.0.1' },
    device: { type: String, default: 'Desktop Browser' },
    status: { type: String, enum: ['SUCCESS', 'WARNING', 'CRITICAL', 'INFO'], default: 'INFO' },
    timestamp: { type: Date, default: Date.now }
  }],
  // Comprehensive Granular Preferences
  notificationPreferences: {
    criticalVulns: {
      inApp: { type: Boolean, default: true },
      email: { type: Boolean, default: true }
    },
    highVulns: {
      inApp: { type: Boolean, default: true },
      email: { type: Boolean, default: true }
    },
    mediumVulns: {
      inApp: { type: Boolean, default: true },
      email: { type: Boolean, default: false }
    },
    scanCompleted: {
      inApp: { type: Boolean, default: true },
      email: { type: Boolean, default: false }
    },
    threatDetected: {
      inApp: { type: Boolean, default: true },
      email: { type: Boolean, default: true }
    },
    assetChanges: {
      inApp: { type: Boolean, default: true },
      email: { type: Boolean, default: false }
    },
    newLogin: {
      inApp: { type: Boolean, default: true },
      email: { type: Boolean, default: true }
    },
    securityChanges: {
      inApp: { type: Boolean, default: true },
      email: { type: Boolean, default: true }
    },
    aiCopilotAlerts: {
      inApp: { type: Boolean, default: true },
      email: { type: Boolean, default: false }
    },
    monitoringAlerts: {
      inApp: { type: Boolean, default: true },
      email: { type: Boolean, default: false }
    },
    reportGenerated: {
      inApp: { type: Boolean, default: true },
      email: { type: Boolean, default: false }
    }
  },
  securityPreferences: {
    loginAlerts: { type: Boolean, default: true },
    newDeviceAlerts: { type: Boolean, default: true },
    suspiciousLoginDetection: { type: Boolean, default: true },
    sessionTimeout: { type: Number, default: 60 } // minutes
  },
  monitoringPreferences: {
    continuousMonitoring: { type: Boolean, default: true },
    vulnerabilityMonitoring: { type: Boolean, default: true },
    threatMonitoring: { type: Boolean, default: true },
    attackSurfaceMonitoring: { type: Boolean, default: true },
    assetHealthAlerts: { type: Boolean, default: true },
    scanIntervalHours: { type: Number, default: 24 }
  },
  aiCopilotPreferences: {
    enabled: { type: Boolean, default: true },
    autoSummaries: { type: Boolean, default: true },
    threatExplanations: { type: Boolean, default: true },
    investigationAssistance: { type: Boolean, default: true },
    alertSuggestions: { type: Boolean, default: true }
  },
  appearancePreferences: {
    theme: { type: String, enum: ['dark', 'light', 'system'], default: 'dark' },
    layout: { type: String, enum: ['comfortable', 'compact'], default: 'comfortable' },
    animations: { type: Boolean, default: true }
  },
  privacyPreferences: {
    activityVisibility: { type: String, default: 'private' },
    sessionHistoryRetention: { type: Number, default: 30 } // days
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

// Indexes
UserSchema.index({ username: 1 });
UserSchema.index({ email: 1 });
UserSchema.index({ role: 1 });
UserSchema.index({ createdAt: -1 });

// Encrypt password using bcrypt before saving
UserSchema.pre('save', async function(next) {
  if (!this.isModified('password')) {
    return next();
  }
  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
  next();
});

// Match user entered password to hashed password in database
UserSchema.methods.matchPassword = async function(enteredPassword) {
  return await bcrypt.compare(enteredPassword, this.password);
};

module.exports = mongoose.model('User', UserSchema);
