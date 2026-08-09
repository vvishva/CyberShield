const express = require('express');
const router = express.Router();
const { processChat } = require('../controllers/copilotController');
const { protect } = require('../middleware/authMiddleware');

router.post('/chat', protect, processChat);

module.exports = router;
