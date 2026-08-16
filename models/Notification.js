const mongoose = require('mongoose');

const NotificationSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: false
  },
  title: {
    type: String,
    required: true
  },
  message: {
    type: String,
    required: true
  },
  type: {
    type: String,
    enum: ['critical', 'high', 'medium', 'low', 'info', 'success', 'warning', 'danger'],
    default: 'info'
  },
  category: {
    type: String,
    enum: ['critical', 'security', 'monitoring', 'system', 'account'],
    default: 'security'
  },
  severity: {
    type: String,
    enum: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'],
    default: 'INFO'
  },
  read: {
    type: Boolean,
    default: false
  },
  eventId: {
    type: String,
    default: () => `EVT-${Math.floor(100000 + Math.random() * 900000)}`
  },
  asset: {
    type: String,
    default: 'CyberShield Sentinel'
  },
  source: {
    type: String,
    default: 'AI Security Engine'
  },
  recommendedAction: {
    type: String,
    default: 'Review event details and check security posture.'
  },
  actionUrl: {
    type: String,
    default: 'scanner.html'
  },
  actionLabel: {
    type: String,
    default: 'View Finding'
  },
  scanId: {
    type: String,
    default: null
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

// Indexes for high performance querying & sorting
NotificationSchema.index({ user: 1, read: 1, createdAt: -1 });
NotificationSchema.index({ user: 1, category: 1, createdAt: -1 });
NotificationSchema.index({ user: 1, severity: 1, createdAt: -1 });
NotificationSchema.index({ createdAt: -1 });

module.exports = mongoose.model('Notification', NotificationSchema);
