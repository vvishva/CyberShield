const User = require('../models/User');
const Log = require('../models/Log');
const Notification = require('../models/Notification');
const Scan = require('../models/Scan');
const MonitoredSite = require('../models/MonitoredSite');
const bcrypt = require('bcryptjs');

// Helper to calculate dynamic Security Score (0-100)
function calculateSecurityScore(user) {
  let score = 30; // base score for registered account
  const checklist = [];

  // 1. Email Verification (+15)
  if (user.isVerified) {
    score += 15;
    checklist.push({ label: 'Email Verified', status: true, key: 'email', icon: 'fa-envelope-circle-check' });
  } else {
    checklist.push({ label: 'Verify Email Address', status: false, key: 'email', icon: 'fa-envelope-open-text' });
  }

  // 2. Mobile Verification (+15)
  if (user.phoneVerified || (user.phoneNumber && user.phoneNumber.length >= 10)) {
    score += 15;
    checklist.push({ label: 'Mobile Device Verified', status: true, key: 'mobile', icon: 'fa-mobile-screen-button' });
  } else {
    checklist.push({ label: 'Add & Verify Mobile Number', status: false, key: 'mobile', icon: 'fa-phone' });
  }

  // 3. Two-Factor Authentication (+20)
  if (user.twoFactorEnabled) {
    score += 20;
    checklist.push({ label: '2FA Multi-Factor Protection Active', status: true, key: '2fa', icon: 'fa-shield-halved' });
  } else {
    checklist.push({ label: 'Enable Two-Factor Authentication', status: false, key: '2fa', icon: 'fa-shield' });
  }

  // 4. Password Health (+10)
  const passwordAgeDays = user.passwordChangedAt 
    ? Math.floor((Date.now() - new Date(user.passwordChangedAt).getTime()) / (1000 * 60 * 60 * 24))
    : 0;
  if (passwordAgeDays <= 90) {
    score += 10;
    checklist.push({ label: 'Strong & Recent Password', status: true, key: 'password', icon: 'fa-key' });
  } else {
    checklist.push({ label: 'Rotate Password (older than 90 days)', status: false, key: 'password', icon: 'fa-rotate' });
  }

  // 5. Active Session & Threat Defense (+10)
  if (user.securityPreferences?.suspiciousLoginDetection !== false) {
    score += 10;
    checklist.push({ label: 'Suspicious Login Detection Active', status: true, key: 'security', icon: 'fa-user-shield' });
  } else {
    checklist.push({ label: 'Activate Heuristic Login Defense', status: false, key: 'security', icon: 'fa-triangle-exclamation' });
  }

  score = Math.min(100, Math.max(0, score));

  let grade = 'Needs Improvement';
  let gradeClass = 'danger';
  if (score >= 90) { grade = 'Excellent Posture'; gradeClass = 'safe'; }
  else if (score >= 75) { grade = 'Strong Security'; gradeClass = 'safe'; }
  else if (score >= 60) { grade = 'Moderate Posture'; gradeClass = 'warning'; }

  return { score, grade, gradeClass, checklist };
}

// Helper to extract device information from user-agent
function parseUserAgent(userAgent = '', reqIp = '127.0.0.1') {
  let os = 'Windows 11';
  if (/android/i.test(userAgent)) os = 'Android';
  else if (/iphone|ipad|ipod/i.test(userAgent)) os = 'iOS';
  else if (/macintosh|mac os x/i.test(userAgent)) os = 'macOS';
  else if (/linux/i.test(userAgent)) os = 'Linux';
  else if (/windows/i.test(userAgent)) os = 'Windows';

  let browser = 'Chrome';
  if (/edg/i.test(userAgent)) browser = 'Edge';
  else if (/firefox/i.test(userAgent)) browser = 'Firefox';
  else if (/safari/i.test(userAgent) && !/chrome/i.test(userAgent)) browser = 'Safari';
  else if (/opera|opr/i.test(userAgent)) browser = 'Opera';

  let device = 'Desktop PC';
  if (/mobile|android|iphone/i.test(userAgent)) device = 'Mobile Phone';
  else if (/tablet|ipad/i.test(userAgent)) device = 'Tablet Device';

  const ip = reqIp.replace('::ffff:', '') || '127.0.0.1';
  return { device, os, browser, ip, location: ip === '127.0.0.1' ? 'Local SOC Sentinel' : 'Authenticated Network' };
}

// @desc    Get Comprehensive User Profile & Security Identity
// @route   GET /api/user/profile
exports.getProfile = async (req, res) => {
  try {
    const user = await User.findById(req.user._id);
    if (!user) {
      return res.status(404).json({ success: false, error: 'User account not found.' });
    }

    const securityRating = calculateSecurityScore(user);

    // Ensure session list exists with current session
    const userAgent = req.headers['user-agent'] || '';
    const reqIp = req.ip || req.connection.remoteAddress || '127.0.0.1';
    const currentParsed = parseUserAgent(userAgent, reqIp);

    if (!user.sessions || user.sessions.length === 0) {
      user.sessions = [{
        device: currentParsed.device,
        os: currentParsed.os,
        browser: currentParsed.browser,
        ip: currentParsed.ip,
        location: currentParsed.location,
        lastActive: new Date(),
        createdAt: new Date(),
        current: true
      }];
      await user.save();
    }

    // Ensure securityActivity exists
    if (!user.securityActivity || user.securityActivity.length === 0) {
      user.securityActivity = [
        { event: 'SOC Security Session Authenticated', ip: currentParsed.ip, device: `${currentParsed.os} (${currentParsed.browser})`, status: 'SUCCESS', timestamp: new Date() },
        { event: 'Initial Identity Credentials Verified', ip: currentParsed.ip, device: 'System Provisioner', status: 'INFO', timestamp: user.createdAt || new Date() }
      ];
      await user.save();
    }

    const connectedAccounts = {
      google: {
        connected: !!user.googleId,
        label: 'Google Workspace OAuth',
        icon: 'fab fa-google',
        email: user.googleId ? user.email : null
      },
      email: {
        connected: !!user.email,
        label: 'Enterprise Email Authentication',
        icon: 'fas fa-envelope',
        verified: !!user.isVerified,
        value: user.email || 'Not configured'
      },
      mobile: {
        connected: !!user.phoneNumber,
        label: 'SMS Multi-Factor Gateway',
        icon: 'fas fa-mobile-screen-button',
        verified: !!user.phoneVerified,
        value: user.phoneNumber || 'Not configured'
      }
    };

    res.status(200).json({
      success: true,
      data: {
        _id: user._id,
        username: user.username,
        fullName: user.fullName || user.username,
        email: user.email,
        phoneNumber: user.phoneNumber,
        country: user.country || 'United States',
        timezone: user.timezone || 'UTC-05:00 (EST)',
        language: user.language || 'English (US)',
        role: user.role,
        status: user.status || 'active',
        avatar: user.avatar || 'avatar-cyber-1.png',
        twoFactorEnabled: !!user.twoFactorEnabled,
        isVerified: !!user.isVerified,
        phoneVerified: !!user.phoneVerified,
        lastLoginAt: user.lastLoginAt || user.createdAt,
        lastLoginIp: user.lastLoginIp || currentParsed.ip,
        lastLoginDevice: user.lastLoginDevice || `${currentParsed.os} (${currentParsed.browser})`,
        passwordChangedAt: user.passwordChangedAt || user.createdAt,
        createdAt: user.createdAt,
        securityRating,
        sessions: user.sessions,
        connectedAccounts,
        securityActivity: user.securityActivity.slice(0, 10)
      }
    });
  } catch (err) {
    console.error('[Profile Fetch Error]', err);
    res.status(500).json({ success: false, error: 'Failed to retrieve profile data.' });
  }
};

// @desc    Update Personal Info & Profile Details
// @route   PUT /api/user/profile
exports.updateProfile = async (req, res) => {
  try {
    const { fullName, phoneNumber, country, timezone, language, avatar } = req.body;
    const user = await User.findById(req.user._id);

    if (!user) {
      return res.status(404).json({ success: false, error: 'User not found.' });
    }

    if (fullName !== undefined) user.fullName = fullName.trim();
    if (phoneNumber !== undefined) user.phoneNumber = phoneNumber ? phoneNumber.trim() : null;
    if (country !== undefined) user.country = country.trim();
    if (timezone !== undefined) user.timezone = timezone.trim();
    if (language !== undefined) user.language = language.trim();
    if (avatar !== undefined) user.avatar = avatar;

    const userAgent = req.headers['user-agent'] || '';
    const reqIp = (req.ip || req.connection.remoteAddress || '127.0.0.1').replace('::ffff:', '');
    const currentParsed = parseUserAgent(userAgent, reqIp);

    user.securityActivity.unshift({
      event: 'Profile Identity Updated',
      ip: currentParsed.ip,
      device: `${currentParsed.os} (${currentParsed.browser})`,
      status: 'INFO',
      timestamp: new Date()
    });

    await user.save();

    // Audit Log
    try {
      await Log.create({
        username: user.username,
        action: 'PROFILE_UPDATED',
        details: 'User modified personal information',
        status: 'SUCCESS'
      });
    } catch (e) {}

    const securityRating = calculateSecurityScore(user);

    res.status(200).json({
      success: true,
      message: 'Profile information updated successfully.',
      data: {
        _id: user._id,
        username: user.username,
        fullName: user.fullName,
        email: user.email,
        phoneNumber: user.phoneNumber,
        country: user.country,
        timezone: user.timezone,
        language: user.language,
        avatar: user.avatar,
        securityRating
      }
    });
  } catch (err) {
    console.error('[Profile Update Error]', err);
    res.status(500).json({ success: false, error: 'Failed to update profile.' });
  }
};

// @desc    Change User Password
// @route   PUT /api/user/password
exports.changePassword = async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;

    if (!currentPassword || !newPassword) {
      return res.status(400).json({ success: false, error: 'Please provide both current and new password.' });
    }

    if (newPassword.length < 8) {
      return res.status(400).json({ success: false, error: 'New password must be at least 8 characters long.' });
    }

    const user = await User.findById(req.user._id).select('+password');
    if (!user) {
      return res.status(404).json({ success: false, error: 'User not found.' });
    }

    const isMatch = await user.matchPassword(currentPassword);
    if (!isMatch) {
      return res.status(400).json({ success: false, error: 'Current password does not match our records.' });
    }

    user.password = newPassword;
    user.passwordChangedAt = new Date();

    const userAgent = req.headers['user-agent'] || '';
    const reqIp = (req.ip || req.connection.remoteAddress || '127.0.0.1').replace('::ffff:', '');
    const currentParsed = parseUserAgent(userAgent, reqIp);

    user.securityActivity.unshift({
      event: 'Account Password Rotated',
      ip: currentParsed.ip,
      device: `${currentParsed.os} (${currentParsed.browser})`,
      status: 'WARNING',
      timestamp: new Date()
    });

    await user.save();

    // Trigger in-app notification
    try {
      await Notification.create({
        user: user._id,
        title: 'Password Successfully Changed',
        message: `Your account password was changed from ${currentParsed.os} (${currentParsed.browser}) at ${new Date().toLocaleTimeString()}.`,
        type: 'warning',
        category: 'account',
        severity: 'MEDIUM',
        asset: 'Security Credentials',
        source: 'Authentication Manager',
        recommendedAction: 'If you did not perform this change, contact your security administrator immediately.'
      });
    } catch (e) {}

    res.status(200).json({
      success: true,
      message: 'Password changed successfully.'
    });
  } catch (err) {
    console.error('[Password Change Error]', err);
    res.status(500).json({ success: false, error: 'Unable to change password.' });
  }
};

// @desc    Toggle 2FA Multi-Factor Authentication
// @route   POST /api/user/2fa/toggle
exports.toggle2FA = async (req, res) => {
  try {
    const user = await User.findById(req.user._id);
    if (!user) {
      return res.status(404).json({ success: false, error: 'User not found.' });
    }

    user.twoFactorEnabled = !user.twoFactorEnabled;

    const userAgent = req.headers['user-agent'] || '';
    const reqIp = (req.ip || req.connection.remoteAddress || '127.0.0.1').replace('::ffff:', '');
    const currentParsed = parseUserAgent(userAgent, reqIp);

    user.securityActivity.unshift({
      event: user.twoFactorEnabled ? '2FA Multi-Factor Protection Enabled' : '2FA Protection Disabled',
      ip: currentParsed.ip,
      device: `${currentParsed.os} (${currentParsed.browser})`,
      status: user.twoFactorEnabled ? 'SUCCESS' : 'WARNING',
      timestamp: new Date()
    });

    await user.save();

    try {
      await Notification.create({
        user: user._id,
        title: user.twoFactorEnabled ? 'Two-Factor Authentication Enabled' : 'Two-Factor Authentication Disabled',
        message: user.twoFactorEnabled 
          ? 'Two-factor authentication is now active on your account.'
          : 'Two-factor authentication was disabled. We recommend keeping 2FA enabled for maximum SOC security.',
        type: user.twoFactorEnabled ? 'success' : 'warning',
        category: 'security',
        severity: user.twoFactorEnabled ? 'LOW' : 'HIGH',
        asset: 'Access Control',
        source: 'Security Operations Center'
      });
    } catch (e) {}

    const securityRating = calculateSecurityScore(user);

    res.status(200).json({
      success: true,
      twoFactorEnabled: user.twoFactorEnabled,
      securityRating,
      message: `Two-Factor Authentication is now ${user.twoFactorEnabled ? 'ENABLED' : 'DISABLED'}.`
    });
  } catch (err) {
    console.error('[2FA Toggle Error]', err);
    res.status(500).json({ success: false, error: 'Failed to update 2FA configuration.' });
  }
};

// @desc    Get Active Login Sessions
// @route   GET /api/user/sessions
exports.getSessions = async (req, res) => {
  try {
    const user = await User.findById(req.user._id);
    if (!user) return res.status(404).json({ success: false, error: 'User not found.' });

    const userAgent = req.headers['user-agent'] || '';
    const reqIp = (req.ip || req.connection.remoteAddress || '127.0.0.1').replace('::ffff:', '');
    const currentParsed = parseUserAgent(userAgent, reqIp);

    if (!user.sessions || user.sessions.length === 0) {
      user.sessions = [{
        device: currentParsed.device,
        os: currentParsed.os,
        browser: currentParsed.browser,
        ip: currentParsed.ip,
        location: currentParsed.location,
        lastActive: new Date(),
        createdAt: new Date(),
        current: true
      }];
      await user.save();
    }

    res.status(200).json({
      success: true,
      data: user.sessions
    });
  } catch (err) {
    res.status(500).json({ success: false, error: 'Failed to retrieve active sessions.' });
  }
};

// @desc    Terminate Specific Session
// @route   DELETE /api/user/sessions/:sessionId
exports.logoutSession = async (req, res) => {
  try {
    const { sessionId } = req.params;
    const user = await User.findById(req.user._id);
    if (!user) return res.status(404).json({ success: false, error: 'User not found.' });

    user.sessions = user.sessions.filter(s => s.sessionId !== sessionId && s._id?.toString() !== sessionId);
    await user.save();

    res.status(200).json({
      success: true,
      message: 'Session terminated successfully.',
      data: user.sessions
    });
  } catch (err) {
    res.status(500).json({ success: false, error: 'Failed to logout session.' });
  }
};

// @desc    Logout All Other Devices & Sessions
// @route   POST /api/user/sessions/logout-others
exports.logoutOtherSessions = async (req, res) => {
  try {
    const user = await User.findById(req.user._id);
    if (!user) return res.status(404).json({ success: false, error: 'User not found.' });

    const userAgent = req.headers['user-agent'] || '';
    const reqIp = (req.ip || req.connection.remoteAddress || '127.0.0.1').replace('::ffff:', '');
    const currentParsed = parseUserAgent(userAgent, reqIp);

    // Keep only the current session
    user.sessions = [{
      device: currentParsed.device,
      os: currentParsed.os,
      browser: currentParsed.browser,
      ip: currentParsed.ip,
      location: currentParsed.location,
      lastActive: new Date(),
      createdAt: new Date(),
      current: true
    }];

    user.securityActivity.unshift({
      event: 'Terminated All Other Device Sessions',
      ip: currentParsed.ip,
      device: `${currentParsed.os} (${currentParsed.browser})`,
      status: 'WARNING',
      timestamp: new Date()
    });

    await user.save();

    res.status(200).json({
      success: true,
      message: 'All other device sessions have been terminated.',
      data: user.sessions
    });
  } catch (err) {
    res.status(500).json({ success: false, error: 'Failed to terminate other sessions.' });
  }
};

// @desc    Get Comprehensive User Settings
// @route   GET /api/user/settings
exports.getSettings = async (req, res) => {
  try {
    const user = await User.findById(req.user._id);
    if (!user) return res.status(404).json({ success: false, error: 'User not found.' });

    res.status(200).json({
      success: true,
      data: {
        notificationPreferences: user.notificationPreferences || {},
        securityPreferences: user.securityPreferences || {},
        monitoringPreferences: user.monitoringPreferences || {},
        aiCopilotPreferences: user.aiCopilotPreferences || {},
        appearancePreferences: user.appearancePreferences || {},
        privacyPreferences: user.privacyPreferences || {}
      }
    });
  } catch (err) {
    res.status(500).json({ success: false, error: 'Failed to load settings.' });
  }
};

// @desc    Update Settings & Preferences
// @route   PUT /api/user/settings
exports.updateSettings = async (req, res) => {
  try {
    const { 
      notificationPreferences, 
      securityPreferences, 
      monitoringPreferences, 
      aiCopilotPreferences, 
      appearancePreferences, 
      privacyPreferences 
    } = req.body;

    const user = await User.findById(req.user._id);
    if (!user) return res.status(404).json({ success: false, error: 'User not found.' });

    if (notificationPreferences) user.notificationPreferences = { ...user.notificationPreferences, ...notificationPreferences };
    if (securityPreferences) user.securityPreferences = { ...user.securityPreferences, ...securityPreferences };
    if (monitoringPreferences) user.monitoringPreferences = { ...user.monitoringPreferences, ...monitoringPreferences };
    if (aiCopilotPreferences) user.aiCopilotPreferences = { ...user.aiCopilotPreferences, ...aiCopilotPreferences };
    if (appearancePreferences) user.appearancePreferences = { ...user.appearancePreferences, ...appearancePreferences };
    if (privacyPreferences) user.privacyPreferences = { ...user.privacyPreferences, ...privacyPreferences };

    await user.save();

    res.status(200).json({
      success: true,
      message: 'Security settings and preferences saved successfully.',
      data: {
        notificationPreferences: user.notificationPreferences,
        securityPreferences: user.securityPreferences,
        monitoringPreferences: user.monitoringPreferences,
        aiCopilotPreferences: user.aiCopilotPreferences,
        appearancePreferences: user.appearancePreferences,
        privacyPreferences: user.privacyPreferences
      }
    });
  } catch (err) {
    console.error('[Settings Save Error]', err);
    res.status(500).json({ success: false, error: 'Failed to save settings.' });
  }
};

// @desc    Disconnect Connected Account Provider (e.g. Google)
// @route   POST /api/user/disconnect-account
exports.disconnectAccount = async (req, res) => {
  try {
    const { provider } = req.body;
    const user = await User.findById(req.user._id);
    if (!user) return res.status(404).json({ success: false, error: 'User not found.' });

    if (provider === 'google') {
      if (!user.email && !user.phoneNumber) {
        return res.status(400).json({ success: false, error: 'Cannot disconnect Google without another recovery method.' });
      }
      user.googleId = null;
      await user.save();

      return res.status(200).json({
        success: true,
        message: 'Google account disconnected successfully.'
      });
    }

    res.status(400).json({ success: false, error: 'Unsupported authentication provider.' });
  } catch (err) {
    res.status(500).json({ success: false, error: 'Failed to disconnect account.' });
  }
};

// @desc    Export Complete Account Data (Download My Data)
// @route   GET /api/user/export-data
exports.exportData = async (req, res) => {
  try {
    const user = await User.findById(req.user._id).lean();
    if (!user) return res.status(404).json({ success: false, error: 'User not found.' });

    delete user.password;
    delete user.verificationOTP;

    const [scans, monitoredSites, notifications, logs] = await Promise.all([
      Scan.find({ user: req.user._id }).lean().catch(() => []),
      MonitoredSite.find({ user: req.user._id }).lean().catch(() => []),
      Notification.find({ user: req.user._id }).lean().catch(() => []),
      Log.find({ username: user.username }).lean().catch(() => [])
    ]);

    const exportBundle = {
      exportMetadata: {
        platform: 'CyberShield AI Security Operations Platform',
        version: '6.0.0',
        exportedAt: new Date().toISOString(),
        userId: user._id,
        recordCounts: {
          scans: scans.length,
          monitoredSites: monitoredSites.length,
          notifications: notifications.length,
          auditLogs: logs.length
        }
      },
      userProfile: user,
      scans,
      monitoredSites,
      notifications,
      auditLogs: logs
    };

    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', `attachment; filename=CyberShield_Data_Export_${user.username}_${Date.now()}.json`);
    res.status(200).send(JSON.stringify(exportBundle, null, 2));
  } catch (err) {
    console.error('[Export Data Error]', err);
    res.status(500).json({ success: false, error: 'Failed to export account data.' });
  }
};

// @desc    Disable User Account (Soft Disable)
// @route   POST /api/user/disable-account
exports.disableAccount = async (req, res) => {
  try {
    const user = await User.findById(req.user._id);
    if (!user) return res.status(404).json({ success: false, error: 'User not found.' });

    user.status = 'disabled';
    await user.save();

    res.status(200).json({
      success: true,
      message: 'Account disabled. You can reactivate by contacting SOC administrator.'
    });
  } catch (err) {
    res.status(500).json({ success: false, error: 'Failed to disable account.' });
  }
};

// @desc    Permanently Delete Account
// @route   DELETE /api/user/account
exports.deleteAccount = async (req, res) => {
  try {
    const { password } = req.body;
    const user = await User.findById(req.user._id).select('+password');

    if (!user) {
      return res.status(404).json({ success: false, error: 'User not found.' });
    }

    if (user.password && password) {
      const isMatch = await user.matchPassword(password);
      if (!isMatch) {
        return res.status(400).json({ success: false, error: 'Invalid password. Deletion cancelled for security.' });
      }
    }

    // Clean up all user associated assets
    await Promise.all([
      User.findByIdAndDelete(user._id),
      Scan.deleteMany({ user: user._id }).catch(() => {}),
      MonitoredSite.deleteMany({ user: user._id }).catch(() => {}),
      Notification.deleteMany({ user: user._id }).catch(() => {})
    ]);

    res.status(200).json({
      success: true,
      message: 'CyberShield account and all associated telemetry permanently deleted.'
    });
  } catch (err) {
    console.error('[Account Deletion Error]', err);
    res.status(500).json({ success: false, error: 'Failed to delete account.' });
  }
};
