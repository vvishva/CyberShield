const mongoose = require('mongoose');

const MonitoredSiteSchema = new mongoose.Schema({
  user:         { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  domain:       { type: String, required: true, trim: true },
  displayName:  { type: String, default: '' },
  interval:     { type: Number, default: 30, min: 10, max: 1440 }, // minutes
  active:       { type: Boolean, default: true },
  lastScan:     { type: Date, default: null },
  nextScan:     { type: Date, default: Date.now },
  lastScore:    { type: Number, default: null },
  lastStatus:   { type: String, default: 'Pending' },
  lastScanId:   { type: mongoose.Schema.Types.ObjectId, ref: 'Scan', default: null },
  scoreHistory: [{ score: Number, date: { type: Date, default: Date.now } }],
  createdAt:    { type: Date, default: Date.now }
});

module.exports = mongoose.model('MonitoredSite', MonitoredSiteSchema);
