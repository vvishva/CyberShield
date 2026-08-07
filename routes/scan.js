const express = require('express');
const router = express.Router();
const {
  scanUrl,
  checkPassword,
  generatePassword,
  scanWebsite,
  checkIp,
  checkFileHash,
  getScanHistory
} = require('../controllers/scanController');

router.post('/url', scanUrl);
router.post('/password', checkPassword);
router.get('/generate-password', generatePassword);
router.post('/website', scanWebsite);
router.post('/ip', checkIp);
router.post('/hash', checkFileHash);
router.get('/history', getScanHistory);

module.exports = router;
