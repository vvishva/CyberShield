const mongoose = require('mongoose');

const IncidentSchema = new mongoose.Schema({
  incidentId: {
    type: String,
    required: true,
    unique: true,
    index: true
  },
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    default: null
  },
  title: {
    type: String,
    required: true,
    trim: true
  },
  severity: {
    type: String,
    enum: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'],
    default: 'MEDIUM'
  },
  status: {
    type: String,
    enum: ['New', 'Investigating', 'Contained', 'Resolved', 'Closed'],
    default: 'New'
  },
  relatedAsset: {
    type: String,
    default: 'CyberShield Core',
    trim: true
  },
  relatedVulnerability: {
    type: String,
    default: ''
  },
  relatedThreat: {
    type: String,
    default: ''
  },
  scanId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Scan',
    default: null
  },
  assignedAnalyst: {
    type: String,
    default: 'SOC Automated Sentinel'
  },
  description: {
    type: String,
    required: true
  },
  impact: {
    type: String,
    default: 'Potential service degradation or unauthorized asset exposure'
  },
  evidence: [{
    key: { type: String },
    value: { type: String },
    detail: { type: String }
  }],
  aiAnalysis: {
    type: String,
    default: ''
  },
  recommendedResponse: {
    type: String,
    default: ''
  },
  investigationNotes: [{
    author: { type: String, default: 'Security Analyst' },
    note: { type: String, required: true },
    timestamp: { type: Date, default: Date.now }
  }],
  timeline: [{
    action: { type: String, required: true },
    detail: { type: String, default: '' },
    user: { type: String, default: 'System' },
    timestamp: { type: Date, default: Date.now }
  }],
  detectionTime: {
    type: Date,
    default: Date.now
  },
  lastUpdated: {
    type: Date,
    default: Date.now
  }
}, {
  timestamps: true
});

module.exports = mongoose.model('Incident', IncidentSchema);
