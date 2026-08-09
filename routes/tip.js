const express = require('express');
const router = express.Router();
const { getTips, createTip } = require('../controllers/tipController');
const { protect } = require('../middleware/authMiddleware');
const { authorize } = require('../middleware/authMiddleware');
const { createTip: createTipValidator } = require('../middleware/validation');

router.get('/', protect, getTips);
router.post('/', protect, authorize('admin'), createTipValidator, createTip);

module.exports = router;
