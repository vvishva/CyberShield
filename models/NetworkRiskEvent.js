const mongoose = require('mongoose');

const NetworkRiskSignalSchema = new mongoose.Schema({
  code: {
    type: String,
    required: true
  },
  name: {
    type: String,
    required: true
  },
  weight: {
    type: Number,
    required: true
  },
  category: {
    type: String,
    enum: ['network', 'behavioral', 'authentication', 'threat'],
    default: 'network'
  },
  detail: {
    type: String,
    default: ''
  }
}, { _id: false });

const NetworkRiskEventSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    default: null,
    index: true
  },
  username: {
    type: String,
    default: 'Anonymous / Guest'
  },
  sessionId: {
    type: String,
    default: null
  },
  ipAddress: {
    type: String,
    required: true,
    index: true
  },
  networkType: {
    type: String,
    enum: ['VPN', 'Proxy', 'Tor', 'Hosting', 'Residential', 'Private/Internal', 'Unknown'],
    default: 'Unknown'
  },
  vpnDetected: {
    type: Boolean,
    default: false
  },
  proxyDetected: {
    type: Boolean,
    default: false
  },
  torDetected: {
    type: Boolean,
    default: false
  },
  hostingDetected: {
    type: Boolean,
    default: false
  },
  country: {
    type: String,
    default: 'Unknown'
  },
  region: {
    type: String,
    default: 'Unknown'
  },
  city: {
    type: String,
    default: 'Unknown'
  },
  isp: {
    type: String,
    default: 'Unknown ISP'
  },
  asn: {
    type: String,
    default: 'N/A'
  },
  failedLoginCount: {
    type: Number,
    default: 0
  },
  suspiciousActivity: {
    type: Boolean,
    default: false
  },
  signals: [NetworkRiskSignalSchema],
  riskScore: {
    type: Number,
    required: true,
    min: 0,
    max: 100,
    index: true
  },
  riskLevel: {
    type: String,
    enum: ['Low', 'Medium', 'High', 'Critical'],
    required: true,
    index: true
  },
  explanation: {
    type: String,
    required: true
  },
  recommendedAction: {
    type: String,
    default: 'Standard defensive monitoring. No immediate action required.'
  },
  status: {
    type: String,
    enum: ['Active', 'Investigating', 'Reviewed', 'Dismissed'],
    default: 'Active'
  },
  reviewed: {
    type: Boolean,
    default: false
  },
  reviewedBy: {
    type: String,
    default: null
  },
  reviewedAt: {
    type: Date,
    default: null
  },
  userAgent: {
    type: String,
    default: ''
  },
  endpoint: {
    type: String,
    default: ''
  },
  actionTaken: {
    type: String,
    default: 'None'
  }
}, {
  timestamps: true
});

// Compound indexes for optimal SOC filtering and querying
NetworkRiskEventSchema.index({ createdAt: -1 });
NetworkRiskEventSchema.index({ riskLevel: 1, createdAt: -1 });
NetworkRiskEventSchema.index({ ipAddress: 1, createdAt: -1 });
NetworkRiskEventSchema.index({ networkType: 1, createdAt: -1 });
NetworkRiskEventSchema.index({ status: 1, createdAt: -1 });

module.exports = mongoose.model('NetworkRiskEvent', NetworkRiskEventSchema);
