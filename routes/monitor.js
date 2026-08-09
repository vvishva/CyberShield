const express = require('express');
const router = express.Router();
const { protect } = require('../middleware/authMiddleware');
const { getSites, addSite, removeSite, toggleSite } = require('../controllers/monitorController');

// All monitor routes require authentication
router.get('/',           protect, getSites);
router.post('/',          protect, addSite);
router.delete('/:id',     protect, removeSite);
router.patch('/:id/toggle', protect, toggleSite);

module.exports = router;
