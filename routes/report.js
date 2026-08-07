const express = require('express');
const router = express.Router();
const { getReports, generateReport, exportCsv } = require('../controllers/reportController');

router.get('/', getReports);
router.post('/generate', generateReport);
router.get('/export-csv', exportCsv);

module.exports = router;
