const mongoose = require('mongoose');

const NetworkRiskConfigSchema = new mongoose.Schema({
  configKey: {
    type: String,
    required: true,
    unique: true,
    default: 'default_config'
  },
  enabled: {
    type: Boolean,
    default: true
  },
  weights: {
    vpn: { type: Number, default: 15 },
    proxy: { type: Number, default: 15 },
    tor: { type: Number, default: 25 },
    hosting: { type: Number, default: 15 },
    failedLogins: { type: Number, default: 20 },
    newSession: { type: Number, default: 10 },
    suspiciousApi: { type: Number, default: 20 },
    sensitiveEndpoint: { type: Number, default: 15 },
    rateLimitViolation: { type: Number, default: 15 }
  },
  thresholds: {
    lowMax: { type: Number, default: 30 },
    mediumMax: { type: Number, default: 60 },
    highMax: { type: Number, default: 80 }
  },
  alertThreshold: {
    type: String,
    enum: ['Low', 'Medium', 'High', 'Critical'],
    default: 'High'
  },
  cacheDurationHours: {
    type: Number,
    default: 24,
    min: 1,
    max: 168
  },
  cooldownMinutes: {
    type: Number,
    default: 5,
    min: 1,
    max: 60
  },
  provider: {
    type: String,
    enum: ['auto', 'local_heuristic', 'proxycheck', 'ipqualityscore', 'ipinfo'],
    default: 'auto'
  },
  updatedBy: {
    type: String,
    default: 'System'
  }
}, {
  timestamps: true
});

module.exports = mongoose.model('NetworkRiskConfig', NetworkRiskConfigSchema);
