// controllers/applicationController.js
const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

// Apply to job (Candidate only)
exports.applyToJob = async (req, res) => {
  try {
    const jobId = parseInt(req.params.jobId);
    const { coverLetter } = req.body;

    // Check if job exists and is active
    const job = await prisma.job.findUnique({
      where: { id: jobId }
    });

    if (!job) {
      return res.status(404).json({ error: 'Job not found' });
    }

    if (!job.isActive) {
      return res.status(400).json({ error: 'Job is not accepting applications' });
    }

    // Check if already applied
    const existingApplication = await prisma.application.findUnique({
      where: {
        candidateId_jobId: {
          candidateId: req.user.id,
          jobId
        }
      }
    });

    if (existingApplication) {
      return res.status(400).json({ error: 'Already applied to this job' });
    }

    // Check if deadline passed
    if (job.applicationDeadline && new Date() > job.applicationDeadline) {
      return res.status(400).json({ error: 'Application deadline has passed' });
    }

    // Create application
    const application = await prisma.application.create({
      data: {
        candidateId: req.user.id,
        jobId,
        coverLetter
      },
      include: {
        job: {
          select: {
            id: true,
            title: true,
            company: true
          }
        }
      }
    });

    res.status(201).json({
      message: 'Application submitted successfully',
      application
    });
  } catch (error) {
    console.error('Apply to job error:', error);
    res.status(500).json({ error: 'Failed to submit application' });
  }
};

// Get candidate's applications
exports.getMyApplications = async (req, res) => {
  try {
    const { status, page = 1, limit = 10 } = req.query;
    
    const where = { candidateId: req.user.id };
    if (status) where.status = status;

    const skip = (parseInt(page) - 1) * parseInt(limit);
    const take = parseInt(limit);

    const [applications, total] = await Promise.all([
      prisma.application.findMany({
        where,
        skip,
        take,
        orderBy: { appliedAt: 'desc' },
        include: {
          job: {
            include: {
              employer: {
                select: {
                  id: true,
                  firstName: true,
                  lastName: true,
                  company: true
                }
              }
            }
          }
        }
      }),
      prisma.application.count({ where })
    ]);

    res.json({
      applications,
      pagination: {
        total,
        page: parseInt(page),
        limit: parseInt(limit),
        totalPages: Math.ceil(total / parseInt(limit))
      }
    });
  } catch (error) {
    console.error('Get my applications error:', error);
    res.status(500).json({ error: 'Failed to get applications' });
  }
};

// Get applications for a job (Employer only)
exports.getJobApplications = async (req, res) => {
  try {
    const jobId = parseInt(req.params.jobId);
    const { status, page = 1, limit = 10 } = req.query;

    // Check if job belongs to employer
    const job = await prisma.job.findUnique({
      where: { id: jobId }
    });

    if (!job) {
      return res.status(404).json({ error: 'Job not found' });
    }

    if (req.user.role === 'EMPLOYER' && job.employerId !== req.user.id) {
      return res.status(403).json({ error: 'Unauthorized to view these applications' });
    }

    const where = { jobId };
    if (status) where.status = status;

    const skip = (parseInt(page) - 1) * parseInt(limit);
    const take = parseInt(limit);

    const [applications, total] = await Promise.all([
      prisma.application.findMany({
        where,
        skip,
        take,
        orderBy: { appliedAt: 'desc' },
        include: {
          candidate: {
            select: {
              id: true,
              firstName: true,
              lastName: true,
              email: true,
              phone: true,
              location: true,
              skills: true,
              experience: true,
              bio: true,
              resume: true
            }
          }
        }
      }),
      prisma.application.count({ where })
    ]);

    res.json({
      applications,
      pagination: {
        total,
        page: parseInt(page),
        limit: parseInt(limit),
        totalPages: Math.ceil(total / parseInt(limit))
      }
    });
  } catch (error) {
    console.error('Get job applications error:', error);
    res.status(500).json({ error: 'Failed to get applications' });
  }
};

// Get single application details
exports.getApplicationById = async (req, res) => {
  try {
    const id = parseInt(req.params.id);

    const application = await prisma.application.findUnique({
      where: { id },
      include: {
        candidate: {
          select: {
            id: true,
            firstName: true,
            lastName: true,
            email: true,
            phone: true,
            location: true,
            skills: true,
            experience: true,
            bio: true,
            resume: true,
            profilePicture: true
          }
        },
        job: {
          include: {
            employer: {
              select: {
                id: true,
                firstName: true,
                lastName: true,
                company: true
              }
            }
          }
        }
      }
    });

    if (!application) {
      return res.status(404).json({ error: 'Application not found' });
    }

    // Check authorization
    if (req.user.role === 'CANDIDATE' && application.candidateId !== req.user.id) {
      return res.status(403).json({ error: 'Unauthorized to view this application' });
    }

    if (req.user.role === 'EMPLOYER' && application.job.employerId !== req.user.id) {
      return res.status(403).json({ error: 'Unauthorized to view this application' });
    }

    res.json(application);
  } catch (error) {
    console.error('Get application by ID error:', error);
    res.status(500).json({ error: 'Failed to get application' });
  }
};

// Update application status (Employer only)
exports.updateApplicationStatus = async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    const { status, notes } = req.body;

    if (!status) {
      return res.status(400).json({ error: 'Status is required' });
    }

    // Check if application exists and belongs to employer's job
    const application = await prisma.application.findUnique({
      where: { id },
      include: {
        job: true
      }
    });

    if (!application) {
      return res.status(404).json({ error: 'Application not found' });
    }

    if (req.user.role === 'EMPLOYER' && application.job.employerId !== req.user.id) {
      return res.status(403).json({ error: 'Unauthorized to update this application' });
    }

    const updatedApplication = await prisma.application.update({
      where: { id },
      data: {
        status,
        notes
      },
      include: {
        candidate: {
          select: {
            id: true,
            firstName: true,
            lastName: true,
            email: true
          }
        }
      }
    });

    res.json({
      message: 'Application status updated successfully',
      application: updatedApplication
    });
  } catch (error) {
    console.error('Update application status error:', error);
    res.status(500).json({ error: 'Failed to update application status' });
  }
};

// Withdraw application (Candidate only)
exports.withdrawApplication = async (req, res) => {
  try {
    const id = parseInt(req.params.id);

    // Check if application exists and belongs to candidate
    const application = await prisma.application.findUnique({
      where: { id }
    });

    if (!application) {
      return res.status(404).json({ error: 'Application not found' });
    }

    if (application.candidateId !== req.user.id) {
      return res.status(403).json({ error: 'Unauthorized to withdraw this application' });
    }

    if (application.status !== 'PENDING' && application.status !== 'REVIEWED') {
      return res.status(400).json({ error: 'Cannot withdraw application at this stage' });
    }

    await prisma.application.delete({
      where: { id }
    });

    res.json({ message: 'Application withdrawn successfully' });
  } catch (error) {
    console.error('Withdraw application error:', error);
    res.status(500).json({ error: 'Failed to withdraw application' });
  }
};

// Get all applications (Admin only)
exports.getAllApplications = async (req, res) => {
  try {
    const { status, jobId, candidateId, page = 1, limit = 10 } = req.query;

    const where = {};
    if (status) where.status = status;
    if (jobId) where.jobId = parseInt(jobId);
    if (candidateId) where.candidateId = parseInt(candidateId);

    const skip = (parseInt(page) - 1) * parseInt(limit);
    const take = parseInt(limit);

    const [applications, total] = await Promise.all([
      prisma.application.findMany({
        where,
        skip,
        take,
        orderBy: { appliedAt: 'desc' },
        include: {
          candidate: {
            select: {
              id: true,
              firstName: true,
              lastName: true,
              email: true
            }
          },
          job: {
            select: {
              id: true,
              title: true,
              company: true
            }
          }
        }
      }),
      prisma.application.count({ where })
    ]);

    res.json({
      applications,
      pagination: {
        total,
        page: parseInt(page),
        limit: parseInt(limit),
        totalPages: Math.ceil(total / parseInt(limit))
      }
    });
  } catch (error) {
    console.error('Get all applications error:', error);
    res.status(500).json({ error: 'Failed to get applications' });
  }
};

// Get application statistics
exports.getApplicationStats = async (req, res) => {
  try {
    const [total, byStatus, recent, topJobs] = await Promise.all([
      prisma.application.count(),
      prisma.application.groupBy({
        by: ['status'],
        _count: true
      }),
      prisma.application.findMany({
        take: 10,
        orderBy: { appliedAt: 'desc' },
        include: {
          candidate: {
            select: {
              firstName: true,
              lastName: true
            }
          },
          job: {
            select: {
              title: true,
              company: true
            }
          }
        }
      }),
      prisma.application.groupBy({
        by: ['jobId'],
        _count: true,
        orderBy: {
          _count: {
            jobId: 'desc'
          }
        },
        take: 5
      })
    ]);

    // Get job details for top jobs
    const topJobDetails = await prisma.job.findMany({
      where: {
        id: {
          in: topJobs.map(j => j.jobId)
        }
      },
      select: {
        id: true,
        title: true,
        company: true
      }
    });

    const topJobsWithDetails = topJobs.map(tj => ({
      ...topJobDetails.find(jd => jd.id === tj.jobId),
      applicationCount: tj._count
    }));

    res.json({
      total,
      byStatus,
      recent,
      topJobs: topJobsWithDetails
    });
  } catch (error) {
    console.error('Get application stats error:', error);
    res.status(500).json({ error: 'Failed to get application statistics' });
  }
};
