const express = require('express');
const router = express.Router();
const { getReports, generateReport, exportCsv } = require('../controllers/reportController');
const { protect } = require('../middleware/authMiddleware');
const { generateReport: generateReportValidator } = require('../middleware/validation');

router.get('/', protect, getReports);
router.post('/generate', protect, generateReportValidator, generateReport);
router.get('/export-csv', protect, exportCsv);

module.exports = router;
