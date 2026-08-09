const mongoose = require('mongoose');

const SecurityTipSchema = new mongoose.Schema({
  title: {
    type: String,
    required: true
  },
  category: {
    type: String,
    enum: ['Password Safety', 'Phishing Awareness', 'Email Hygiene', 'Safe Browsing', 'Network Security', 'General Cyber'],
    default: 'General Cyber'
  },
  content: {
    type: String,
    required: true
  },
  severity: {
    type: String,
    enum: ['INFO', 'IMPORTANT', 'CRITICAL'],
    default: 'INFO'
  },
  author: {
    type: String,
    default: 'CyberShield Intelligence Team'
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

// Indexes
SecurityTipSchema.index({ category: 1, createdAt: -1 });
SecurityTipSchema.index({ severity: 1, createdAt: -1 });
SecurityTipSchema.index({ createdAt: -1 });
SecurityTipSchema.index({ title: 'text', content: 'text' });

module.exports = mongoose.model('SecurityTip', SecurityTipSchema);
