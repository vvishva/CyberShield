const express = require('express');
const router = express.Router();
const { getUsers, deleteUser, getLogs, getStats } = require('../controllers/adminController');
const { protect } = require('../middleware/authMiddleware');
const { admin } = require('../middleware/adminMiddleware');

router.get('/users', getUsers);
router.delete('/users/:id', deleteUser);
router.get('/logs', getLogs);
router.get('/stats', getStats);

module.exports = router;
