const express = require('express');
const router = express.Router();
const applicationController = require('../controllers/applicationController');
const { auth } = require('../middleware/auth');
const { candidateAuth, employerAuth, adminAuth } = require('../middleware/roleAuth');

// Candidate routes
router.post('/jobs/:jobId/apply', auth, candidateAuth, applicationController.applyToJob);
router.get('/my-applications', auth, candidateAuth, applicationController.getMyApplications);
router.delete('/:id/withdraw', auth, candidateAuth, applicationController.withdrawApplication);

// Employer routes
router.get('/jobs/:jobId/applications', auth, employerAuth, applicationController.getJobApplications);
router.put('/:id/status', auth, employerAuth, applicationController.updateApplicationStatus);

// Shared routes (candidate can view their own, employer can view for their jobs)
router.get('/:id', auth, applicationController.getApplicationById);

// Admin routes
router.get('/', auth, adminAuth, applicationController.getAllApplications);
router.get('/stats/overview', auth, adminAuth, applicationController.getApplicationStats);

module.exports = router;