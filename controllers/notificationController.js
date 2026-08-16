const Notification = require('../models/Notification');
const User = require('../models/User');

// Helper to seed realistic enterprise SOC notifications if user has zero notifications
async function seedInitialNotifications(userId) {
  const initialAlerts = [
    {
      user: userId,
      title: 'Critical SSL/TLS Protocol Downgrade Vulnerability',
      message: 'A monitored endpoint was detected accepting outdated TLS 1.0/1.1 cipher suites with known vulnerabilities.',
      type: 'critical',
      category: 'critical',
      severity: 'CRITICAL',
      read: false,
      eventId: `EVT-${Math.floor(100000 + Math.random() * 900000)}`,
      asset: 'api.production-core.internal',
      source: 'Vulnerability Sentinel Engine',
      recommendedAction: 'Enforce TLS 1.3 only and disable deprecated weak cipher suites immediately.',
      actionUrl: 'vulnerabilities.html',
      actionLabel: 'View Finding',
      createdAt: new Date(Date.now() - 15 * 60 * 1000)
    },
    {
      user: userId,
      title: 'Real-time AI Threat Intelligence Match',
      message: 'Suspicious outbound traffic pattern matching known phishing beacon signature detected and neutralized.',
      type: 'danger',
      category: 'security',
      severity: 'HIGH',
      read: false,
      eventId: `EVT-${Math.floor(100000 + Math.random() * 900000)}`,
      asset: 'Gateway Firewall Sentinel',
      source: 'AI Threat Intelligence Feed',
      recommendedAction: 'Review source IP telemetry and initiate deep threat investigation.',
      actionUrl: 'investigation.html',
      actionLabel: 'Investigate Threat',
      createdAt: new Date(Date.now() - 45 * 60 * 1000)
    },
    {
      user: userId,
      title: 'Continuous Monitoring Health Check Complete',
      message: 'Automated 24-hour baseline vulnerability sweep completed across all active monitored endpoints.',
      type: 'info',
      category: 'monitoring',
      severity: 'LOW',
      read: false,
      eventId: `EVT-${Math.floor(100000 + Math.random() * 900000)}`,
      asset: 'Monitored Asset Fleet',
      source: 'Continuous Auto-Monitoring',
      recommendedAction: 'Inspect score drift trends in the continuous monitoring console.',
      actionUrl: 'monitor.html',
      actionLabel: 'View Assets',
      createdAt: new Date(Date.now() - 2 * 3600 * 1000)
    },
    {
      user: userId,
      title: 'New Device Authentication Verified',
      message: 'Successful SOC session initiated from authenticated workstation.',
      type: 'success',
      category: 'account',
      severity: 'INFO',
      read: true,
      eventId: `EVT-${Math.floor(100000 + Math.random() * 900000)}`,
      asset: 'Identity Access Gateway',
      source: 'Authentication Manager',
      recommendedAction: 'No action required if this login was initiated by you.',
      actionUrl: 'profile.html',
      actionLabel: 'Review Sessions',
      createdAt: new Date(Date.now() - 5 * 3600 * 1000)
    }
  ];

  try {
    return await Notification.insertMany(initialAlerts);
  } catch (e) {
    return [];
  }
}

// @desc    Get User Notifications with Filtering & Search
// @route   GET /api/notifications
exports.getNotifications = async (req, res) => {
  try {
    const { category, severity, read, search, limit = 50 } = req.query;

    const query = {
      $or: [
        { user: req.user._id },
        { user: null } // broadcast / system-wide
      ]
    };

    if (category && category !== 'all') {
      query.category = category.toLowerCase();
    }

    if (severity && severity !== 'all') {
      query.severity = severity.toUpperCase();
    }

    if (read !== undefined && read !== 'all') {
      query.read = read === 'true';
    }

    if (search && search.trim()) {
      const regex = new RegExp(search.trim(), 'i');
      query.$and = query.$and || [];
      query.$and.push({
        $or: [
          { title: regex },
          { message: regex },
          { asset: regex },
          { eventId: regex }
        ]
      });
    }

    let notifications = await Notification.find(query)
      .sort({ createdAt: -1 })
      .limit(parseInt(limit));

    // If zero notifications exist for the user, auto-seed initial realistic SOC alerts
    if (notifications.length === 0 && (!category || category === 'all') && (!search)) {
      notifications = await seedInitialNotifications(req.user._id);
    }

    const unreadCount = await Notification.countDocuments({
      $or: [{ user: req.user._id }, { user: null }],
      read: false
    });

    res.status(200).json({
      success: true,
      count: notifications.length,
      unreadCount,
      data: notifications
    });
  } catch (err) {
    console.error('[Get Notifications Error]', err);
    res.status(500).json({ success: false, error: 'Failed to fetch notifications.' });
  }
};

// @desc    Get Fast Unread Count for Badges
// @route   GET /api/notifications/count
exports.getUnreadCount = async (req, res) => {
  try {
    const unreadCount = await Notification.countDocuments({
      $or: [{ user: req.user._id }, { user: null }],
      read: false
    });

    res.status(200).json({
      success: true,
      unreadCount
    });
  } catch (err) {
    res.status(500).json({ success: false, unreadCount: 0 });
  }
};

// @desc    Mark Single Notification as Read
// @route   PUT /api/notifications/:id/read
exports.markAsRead = async (req, res) => {
  try {
    const notification = await Notification.findOneAndUpdate(
      { _id: req.params.id, $or: [{ user: req.user._id }, { user: null }] },
      { read: true },
      { new: true }
    );

    if (!notification) {
      return res.status(404).json({ success: false, error: 'Notification not found.' });
    }

    const unreadCount = await Notification.countDocuments({
      $or: [{ user: req.user._id }, { user: null }],
      read: false
    });

    res.status(200).json({
      success: true,
      unreadCount,
      data: notification
    });
  } catch (err) {
    res.status(500).json({ success: false, error: 'Failed to update notification.' });
  }
};

// @desc    Mark All Notifications as Read
// @route   PUT /api/notifications/read-all
exports.markAllAsRead = async (req, res) => {
  try {
    await Notification.updateMany(
      { $or: [{ user: req.user._id }, { user: null }], read: false },
      { read: true }
    );

    res.status(200).json({
      success: true,
      message: 'All notifications marked as read.',
      unreadCount: 0
    });
  } catch (err) {
    res.status(500).json({ success: false, error: 'Failed to mark all as read.' });
  }
};

// @desc    Delete Single Notification
// @route   DELETE /api/notifications/:id
exports.deleteNotification = async (req, res) => {
  try {
    const notification = await Notification.findOneAndDelete({
      _id: req.params.id,
      $or: [{ user: req.user._id }, { user: null }]
    });

    if (!notification) {
      return res.status(404).json({ success: false, error: 'Notification not found.' });
    }

    const unreadCount = await Notification.countDocuments({
      $or: [{ user: req.user._id }, { user: null }],
      read: false
    });

    res.status(200).json({
      success: true,
      message: 'Notification removed.',
      unreadCount
    });
  } catch (err) {
    res.status(500).json({ success: false, error: 'Failed to delete notification.' });
  }
};

// @desc    Clear All Read Notifications
// @route   DELETE /api/notifications/clear-read
exports.clearReadNotifications = async (req, res) => {
  try {
    await Notification.deleteMany({
      $or: [{ user: req.user._id }, { user: null }],
      read: true
    });

    res.status(200).json({
      success: true,
      message: 'All read notifications cleared.'
    });
  } catch (err) {
    res.status(500).json({ success: false, error: 'Failed to clear read notifications.' });
  }
};
