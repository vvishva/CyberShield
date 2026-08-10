const express = require('express');
const router = express.Router();
const { processChat } = require('../controllers/copilotController');
const { optionalAuth } = require('../middleware/authMiddleware');

router.post('/chat', optionalAuth, processChat);

module.exports = router;
