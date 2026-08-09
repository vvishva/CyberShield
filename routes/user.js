const express = require('express');
const router = express.Router();
const { getProfile, updateProfile, deleteAccount } = require('../controllers/userController');
const { protect } = require('../middleware/authMiddleware');
const { updateProfile: updateProfileValidator } = require('../middleware/validation');

router.get('/profile', protect, getProfile);
router.put('/profile', protect, updateProfileValidator, updateProfile);
router.delete('/profile', protect, deleteAccount);

module.exports = router;
