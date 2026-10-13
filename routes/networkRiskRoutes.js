const express = require('express');
const router = express.Router();
const { protect, authorize } = require('../middleware/authMiddleware');
const {
  getSummary,
  getEvents,
  getEventById,
  markReviewed,
  manualCheckIp,
  getConfigSettings,
  updateConfigSettings
} = require('../controllers/networkRiskController');

// All endpoints require authenticated session
router.use(protect);

router.get('/summary', getSummary);
router.get('/events', getEvents);
router.get('/events/:id', getEventById);
router.patch('/events/:id/review', markReviewed);
router.post('/check-ip', manualCheckIp);

// Admin-restricted configuration routes
router.get('/config', authorize('admin'), getConfigSettings);
router.put('/config', authorize('admin'), updateConfigSettings);

module.exports = router;
