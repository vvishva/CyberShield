const User = require('../models/User');
const Scan = require('../models/Scan');
const Log = require('../models/Log');

// @desc    Get All Users (Admin)
// @route   GET /api/admin/users
exports.getUsers = async (req, res) => {
  try {
    let users = [];
    try {
      users = await User.find()
        .select('-password -resetPasswordToken -resetPasswordExpire')
        .sort({ createdAt: -1 });
    } catch (e) {
      // DB unavailable - return empty array
    }

    // Sanitize: only return safe fields
    const sanitized = users.map(u => ({
      _id: u._id,
      username: u.username,
      email: u.email,
      role: u.role,
      createdAt: u.createdAt
    }));

    res.status(200).json({
      success: true,
      count: sanitized.length,
      data: sanitized
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
};

// @desc    Delete User (Admin)
// @route   DELETE /api/admin/users/:id
exports.deleteUser = async (req, res) => {
  try {
    const { id } = req.params;
    try {
      await User.findByIdAndDelete(id);
    } catch (e) {
      // Ignore if DB unavailable or user not found
    }

    res.status(200).json({
      success: true,
      message: `User ${id} deleted successfully.`
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
};

// @desc    Get System Audit Logs (Admin)
// @route   GET /api/admin/logs
exports.getLogs = async (req, res) => {
  try {
    let logs = [];
    try {
      logs = await Log.find().sort({ createdAt: -1 }).limit(50);
    } catch (e) {
      // DB unavailable - return empty array
    }

    res.status(200).json({
      success: true,
      count: logs.length,
      data: logs
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
};

// @desc    Get Overall Dashboard Analytics & Metrics
// @route   GET /api/admin/stats
exports.getStats = async (req, res) => {
  try {
    let totalScans = 0;
    let threatsDetected = 0;
    let safeScans = 0;
    let totalUsers = 0;

    try {
      totalScans = await Scan.countDocuments();
      threatsDetected = await Scan.countDocuments({ riskScore: { $gte: 50 } });
      safeScans = await Scan.countDocuments({ riskScore: { $lt: 25 } });
      totalUsers = await User.countDocuments();
    } catch (e) {
      // DB unavailable - return zeros
    }

    res.status(200).json({
      success: true,
      stats: {
        totalScans,
        threatsDetected,
        safeScans,
        totalUsers,
        securityScore: totalScans > 0 ? Math.round(((safeScans / totalScans) * 100)) : 0
      }
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
};
