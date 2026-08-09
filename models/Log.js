const mongoose = require('mongoose');

const LogSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: false
  },
  username: {
    type: String,
    default: 'Anonymous'
  },
  action: {
    type: String,
    required: true
  },
  details: {
    type: String,
    default: ''
  },
  ipAddress: {
    type: String,
    default: '127.0.0.1'
  },
  userAgent: {
    type: String,
    default: 'Web Agent'
  },
  status: {
    type: String,
    enum: ['SUCCESS', 'WARNING', 'FAILURE'],
    default: 'SUCCESS'
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

// Indexes for query performance
LogSchema.index({ user: 1, createdAt: -1 });
LogSchema.index({ action: 1, createdAt: -1 });
LogSchema.index({ status: 1, createdAt: -1 });
LogSchema.index({ username: 1, createdAt: -1 });
LogSchema.index({ createdAt: -1 });

module.exports = mongoose.model('Log', LogSchema);
