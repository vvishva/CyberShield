const express = require('express');
const router = express.Router();
const { getTips, createTip } = require('../controllers/tipController');

router.get('/', getTips);
router.post('/', createTip);

module.exports = router;
