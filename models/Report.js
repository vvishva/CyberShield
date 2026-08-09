const mongoose = require('mongoose');

const ReportSchema = new mongoose.Schema({
  reportId: {
    type: String,
    required: true,
    unique: true
  },
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: false
  },
  title: {
    type: String,
    required: true
  },
  scanType: {
    type: String,
    required: true
  },
  target: {
    type: String,
    required: true
  },
  overallStatus: {
    type: String,
    required: true
  },
  riskScore: {
    type: Number,
    required: true
  },
  findings: [{
    category: String,
    status: String,
    detail: String
  }],
  recommendations: [String],
  createdAt: {
    type: Date,
    default: Date.now
  }
});

// Indexes
ReportSchema.index({ user: 1, createdAt: -1 });
ReportSchema.index({ reportId: 1 }, { unique: true });
ReportSchema.index({ scanType: 1, createdAt: -1 });
ReportSchema.index({ target: 'text' });
ReportSchema.index({ createdAt: -1 });

module.exports = mongoose.model('Report', ReportSchema);
