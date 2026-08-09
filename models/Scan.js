const mongoose = require('mongoose');

const ScanSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: false
  },
  scanType: {
    type: String,
    enum: ['url_phishing', 'website_security', 'ip_reputation', 'file_hash', 'password_check'],
    required: true
  },
  target: {
    type: String,
    required: true
  },
  status: {
    type: String,
    enum: ['Safe', 'Suspicious', 'Phishing', 'Medium Risk', 'High Risk', 'Weak', 'Strong'],
    required: true
  },
  riskScore: {
    type: Number,
    min: 0,
    max: 100,
    default: 0
  },
  confidenceScore: {
    type: Number,
    min: 0,
    max: 100,
    default: 95
  },
  details: {
    type: mongoose.Schema.Types.Mixed,
    default: {}
  },
  recommendations: [{
    type: String
  }],
  createdAt: {
    type: Date,
    default: Date.now
  }
});

// Indexes for query performance
ScanSchema.index({ user: 1, createdAt: -1 });
ScanSchema.index({ scanType: 1, status: 1 });
ScanSchema.index({ target: 'text' });
ScanSchema.index({ riskScore: -1 });
ScanSchema.index({ createdAt: -1 });

module.exports = mongoose.model('Scan', ScanSchema);
