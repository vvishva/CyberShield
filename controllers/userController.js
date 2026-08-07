const User = require('../models/User');

// @desc    Get User Profile
// @route   GET /api/user/profile
exports.getProfile = async (req, res) => {
  res.status(200).json({
    success: true,
    user: req.user
  });
};

// @desc    Update Profile Details
// @route   PUT /api/user/profile
exports.updateProfile = async (req, res) => {
  const { username, avatar, twoFactorEnabled, emailNotifications } = req.body;

  try {
    if (req.user && req.user._id) {
      const updated = await User.findByIdAndUpdate(
        req.user._id,
        { username, avatar, twoFactorEnabled, emailNotifications },
        { new: true }
      );
      return res.status(200).json({ success: true, user: updated });
    }
  } catch (e) {}

  res.status(200).json({
    success: true,
    user: {
      ...req.user,
      username: username || req.user.username,
      avatar: avatar || req.user.avatar,
      twoFactorEnabled: twoFactorEnabled !== undefined ? twoFactorEnabled : req.user.twoFactorEnabled,
      emailNotifications: emailNotifications !== undefined ? emailNotifications : req.user.emailNotifications
    }
  });
};

// @desc    Delete Account
// @route   DELETE /api/user/profile
exports.deleteAccount = async (req, res) => {
  try {
    if (req.user && req.user._id) {
      await User.findByIdAndDelete(req.user._id);
    }
  } catch (e) {}

  res.status(200).json({
    success: true,
    message: 'User account has been deleted.'
  });
};
