const express = require('express');
const router = express.Router();
const { protect } = require('../middleware/auth');
const {
  getIncidents,
  getIncidentById,
  createIncident,
  updateIncidentStatus,
  addInvestigationNote,
  aiAnalyzeIncident
} = require('../controllers/incidentController');

router.use(protect);

router.route('/')
  .get(getIncidents)
  .post(createIncident);

router.route('/:id')
  .get(getIncidentById);

router.route('/:id/status')
  .patch(updateIncidentStatus);

router.route('/:id/notes')
  .post(addInvestigationNote);

router.route('/:id/ai-analyze')
  .post(aiAnalyzeIncident);

module.exports = router;
