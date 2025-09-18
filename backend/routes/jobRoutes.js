const express = require('express');
const router = express.Router();
const jobController = require('../controllers/jobController');
const { auth, optionalAuth } = require('../middleware/auth');
const { employerAuth, candidateAuth, adminAuth } = require('../middleware/roleAuth');

// Public routes (optional authentication for tracking saved/applied status)
router.get('/', optionalAuth, jobController.getAllJobs);
router.get('/:id', optionalAuth, jobController.getJobById);

// Employer routes
router.post('/', auth, employerAuth, jobController.createJob);
router.put('/:id', auth, employerAuth, jobController.updateJob);
router.delete('/:id', auth, employerAuth, jobController.deleteJob);
router.get('/employer/my-jobs', auth, employerAuth, jobController.getEmployerJobs);
router.get('/employer/:employerId/jobs', auth, jobController.getEmployerJobs); // Note: Corrected param name from ':employerld'

// Candidate routes
router.post('/:id/save', auth, candidateAuth, jobController.toggleSaveJob);
router.get('/saved/my-jobs', auth, candidateAuth, jobController.getSavedJobs);

// Admin routes
router.get('/stats/overview', auth, adminAuth, jobController.getJobStats);

module.exports = router;