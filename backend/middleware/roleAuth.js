// Admin only middleware
const adminAuth = async (req, res, next) => {
  try {
    if (req.user.role !== 'ADMIN') {
      return res.status(403).json({ 
        error: 'Access denied',
        message: 'Admin privileges required'
      });
    }
    next();
  } catch (error) {
    res.status(403).json({ error: 'Access denied' });
  }
};

// Employer or Admin
const employerAuth = async (req, res, next) => {
  try {
    if (req.user.role !== 'EMPLOYER' && req.user.role !== 'ADMIN') {
      return res.status(403).json({ 
        error: 'Access denied',
        message: 'Employer privileges required'
      });
    }
    next();
  } catch (error) {
    res.status(403).json({ error: 'Access denied' });
  }
};

// Candidate only
const candidateAuth = async (req, res, next) => {
  try {
    if (req.user.role !== 'CANDIDATE' && req.user.role !== 'ADMIN') {
      return res.status(403).json({ 
        error: 'Access denied',
        message: 'Candidate privileges required'
      });
    }
    next();
  } catch (error) {
    res.status(403).json({ error: 'Access denied' });
  }
};

module.exports = { 
  adminAuth, 
  employerAuth, 
  candidateAuth 
};
