const express = require('express');
const router = express.Router();
const { getReports, generateReport, exportCsv, downloadPdf } = require('../controllers/reportController');
const { protect } = require('../middleware/authMiddleware');
const { generateReport: generateReportValidator } = require('../middleware/validation');

router.get('/', protect, getReports);
router.post('/generate', protect, generateReportValidator, generateReport);
router.get('/export-csv', protect, exportCsv);
router.post('/download-pdf', protect, downloadPdf);
router.get('/download-pdf/:id', protect, downloadPdf);

module.exports = router;
