const express = require('express');
const router = express.Router();
const { getUsers, deleteUser, getLogs, getStats } = require('../controllers/adminController');
const { protect } = require('../middleware/authMiddleware');
const { authorize } = require('../middleware/authMiddleware');
const { mongoId } = require('../middleware/validation');

router.use(protect);
router.use(authorize('admin'));

router.get('/users', getUsers);
router.delete('/users/:id', mongoId, deleteUser);
router.get('/logs', getLogs);
router.get('/stats', getStats);

module.exports = router;
