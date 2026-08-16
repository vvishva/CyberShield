const express = require('express');
const router = express.Router();
const { 
  getProfile, 
  updateProfile, 
  changePassword, 
  toggle2FA, 
  getSessions, 
  logoutSession, 
  logoutOtherSessions, 
  getSettings, 
  updateSettings, 
  disconnectAccount, 
  exportData, 
  disableAccount, 
  deleteAccount 
} = require('../controllers/userController');
const { protect } = require('../middleware/authMiddleware');

// Profile & Identity Endpoints
router.get('/profile', protect, getProfile);
router.put('/profile', protect, updateProfile);
router.put('/password', protect, changePassword);
router.post('/2fa/toggle', protect, toggle2FA);

// Session & Device Management Endpoints
router.get('/sessions', protect, getSessions);
router.delete('/sessions/:sessionId', protect, logoutSession);
router.post('/sessions/logout-others', protect, logoutOtherSessions);

// Settings & Preferences Endpoints
router.get('/settings', protect, getSettings);
router.put('/settings', protect, updateSettings);

// Account Actions & Data Privacy
router.post('/disconnect-account', protect, disconnectAccount);
router.get('/export-data', protect, exportData);
router.post('/disable-account', protect, disableAccount);
router.delete('/account', protect, deleteAccount);

module.exports = router;
