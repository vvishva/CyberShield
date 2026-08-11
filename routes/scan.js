const express = require('express');
const router = express.Router();
const {
  scanUrl,
  checkPassword,
  generatePassword,
  scanWebsite,
  checkIp,
  checkFileHash,
  getScanHistory,
  getStats,
  getDashboardSummary,
  getMonitoredAssets,
  addMonitoredAsset,
  toggleMonitoredAsset,
  removeMonitoredAsset,
  scanNowMonitoredAsset
} = require('../controllers/scanController');
const { protect } = require('../middleware/authMiddleware');
const { scanUrl: scanUrlValidator, scanWebsite: scanWebsiteValidator, scanPassword: scanPasswordValidator, scanIp: scanIpValidator, scanHash: scanHashValidator } = require('../middleware/validation');

router.post('/url', protect, scanUrlValidator, scanUrl);
router.post('/password', protect, scanPasswordValidator, checkPassword);
router.get('/generate-password', protect, generatePassword);
router.post('/website', protect, scanWebsiteValidator, scanWebsite);
router.post('/ip', protect, scanIpValidator, checkIp);
router.post('/hash', protect, scanHashValidator, checkFileHash);
router.get('/history', protect, getScanHistory);
router.get('/stats', protect, getStats);
router.get('/dashboard-summary', protect, getDashboardSummary);

// Monitoring Routes
router.get('/monitored', protect, getMonitoredAssets);
router.post('/monitored/add', protect, addMonitoredAsset);
router.post('/monitored/toggle', protect, toggleMonitoredAsset);
router.post('/monitored/remove', protect, removeMonitoredAsset);
router.post('/monitored/scan-now', protect, scanNowMonitoredAsset);

module.exports = router;
