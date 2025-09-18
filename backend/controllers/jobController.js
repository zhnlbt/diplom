// controllers/jobController.js
const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

// Create new job (Employer only)
exports.createJob = async (req, res) => {
  try {
    const {
      title,
      description,
      company,
      location,
      salary,
      salaryMin,
      salaryMax,
      jobType,
      requirements,
      benefits,
      applicationDeadline
    } = req.body;

    // Validate required fields
    if (!title || !description || !location || !jobType) {
      return res.status(400).json({
        error: 'Missing required fields',
        required: ['title', 'description', 'location', 'jobType']
      });
    }

    const job = await prisma.job.create({
      data: {
        title,
        description,
        company: company || req.user.company,
        location,
        salary,
        salaryMin,
        salaryMax,
        jobType,
        requirements: requirements || [],
        benefits: benefits || [],
        applicationDeadline: applicationDeadline ? new Date(applicationDeadline) : null,
        employerId: req.user.id
      },
      include: {
        employer: {
          select: {
            id: true,
            firstName: true,
            lastName: true,
            company: true,
            email: true
          }
        }
      }
    });

    res.status(201).json({
      message: 'Job created successfully',
      job
    });
  } catch (error) {
    console.error('Create job error:', error);
    res.status(500).json({ error: 'Failed to create job' });
  }
};

// Get all jobs (with filters)
exports.getAllJobs = async (req, res) => {
  try {
    const {
      search,
      jobType,
      location,
      salaryMin,
      salaryMax,
      company,
      isActive = 'true',
      page = 1,
      limit = 10,
      sortBy = 'createdAt',
      order = 'desc'
    } = req.query;

    const where = {
      isActive: isActive === 'true'
    };

    // Add filters
    if (search) {
      where.OR = [
        { title: { contains: search, mode: 'insensitive' } },
        { description: { contains: search, mode: 'insensitive' } },
        { company: { contains: search, mode: 'insensitive' } }
      ];
    }

    if (jobType) where.jobType = jobType;
    if (location) where.location = { contains: location, mode: 'insensitive' };
    if (company) where.company = { contains: company, mode: 'insensitive' };
    
    if (salaryMin || salaryMax) {
      where.AND = [];
      if (salaryMin) where.AND.push({ salaryMin: { gte: parseInt(salaryMin) } });
      if (salaryMax) where.AND.push({ salaryMax: { lte: parseInt(salaryMax) } });
    }

    // Check if not past deadline
    where.OR = where.OR || [];
    where.OR.push(
      { applicationDeadline: null },
      { applicationDeadline: { gte: new Date() } }
    );

    const skip = (parseInt(page) - 1) * parseInt(limit);
    const take = parseInt(limit);

    const [jobs, total] = await Promise.all([
      prisma.job.findMany({
        where,
        skip,
        take,
        orderBy: { [sortBy]: order },
        include: {
          employer: {
            select: {
              id: true,
              firstName: true,
              lastName: true,
              company: true,
              companyWebsite: true
            }
          },
          _count: {
            select: {
              applications: true,
              savedBy: true
            }
          }
        }
      }),
      prisma.job.count({ where })
    ]);

    // Increment view count for listed jobs
    if (jobs.length > 0) {
      await prisma.job.updateMany({
        where: {
          id: { in: jobs.map(job => job.id) }
        },
        data: {
          viewCount: { increment: 1 }
        }
      });
    }

    res.json({
      jobs,
      pagination: {
        total,
        page: parseInt(page),
        limit: parseInt(limit),
        totalPages: Math.ceil(total / parseInt(limit))
      }
    });
  } catch (error) {
    console.error('Get all jobs error:', error);
    res.status(500).json({ error: 'Failed to get jobs' });
  }
};

// Get single job by ID
exports.getJobById = async (req, res) => {
  try {
    const id = parseInt(req.params.id);

    const job = await prisma.job.findUnique({
      where: { id },
      include: {
        employer: {
          select: {
            id: true,
            firstName: true,
            lastName: true,
            company: true,
            companyWebsite: true,
            bio: true,
            location: true
          }
        },
        applications: req.user && req.user.role === 'EMPLOYER' ? {
          select: {
            id: true,
            status: true,
            appliedAt: true,
            candidate: {
              select: {
                id: true,
                firstName: true,
                lastName: true,
                email: true
              }
            }
          }
        } : false,
        _count: {
          select: {
            applications: true,
            savedBy: true
          }
        }
      }
    });

    if (!job) {
      return res.status(404).json({ error: 'Job not found' });
    }

    // Increment view count
    await prisma.job.update({
      where: { id },
      data: { viewCount: { increment: 1 } }
    });

    // Check if current user has applied or saved
    if (req.user && req.user.role === 'CANDIDATE') {
      const [application, saved] = await Promise.all([
        prisma.application.findUnique({
          where: {
            candidateId_jobId: {
              candidateId: req.user.id,
              jobId: id
            }
          }
        }),
        prisma.savedJob.findUnique({
          where: {
            userId_jobId: {
              userId: req.user.id,
              jobId: id
            }
          }
        })
      ]);

      job.hasApplied = !!application;
      job.applicationStatus = application?.status;
      job.isSaved = !!saved;
    }

    res.json(job);
  } catch (error) {
    console.error('Get job by ID error:', error);
    res.status(500).json({ error: 'Failed to get job' });
  }
};

// Update job (Employer only)
exports.updateJob = async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    const {
      title,
      description,
      location,
      salary,
      salaryMin,
      salaryMax,
      jobType,
      requirements,
      benefits,
      applicationDeadline,
      isActive
    } = req.body;

    // Check if job exists and belongs to employer
    const existingJob = await prisma.job.findUnique({
      where: { id }
    });

    if (!existingJob) {
      return res.status(404).json({ error: 'Job not found' });
    }

    if (req.user.role === 'EMPLOYER' && existingJob.employerId !== req.user.id) {
      return res.status(403).json({ error: 'Unauthorized to update this job' });
    }

    const updatedJob = await prisma.job.update({
      where: { id },
      data: {
        title,
        description,
        location,
        salary,
        salaryMin,
        salaryMax,
        jobType,
        requirements,
        benefits,
        applicationDeadline: applicationDeadline ? new Date(applicationDeadline) : undefined,
        isActive
      },
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
    });

    res.json({
      message: 'Job updated successfully',
      job: updatedJob
    });
  } catch (error) {
    console.error('Update job error:', error);
    res.status(500).json({ error: 'Failed to update job' });
  }
};

// Delete job (Employer only)
exports.deleteJob = async (req, res) => {
  try {
    const id = parseInt(req.params.id);

    // Check if job exists and belongs to employer
    const job = await prisma.job.findUnique({
      where: { id }
    });

    if (!job) {
      return res.status(404).json({ error: 'Job not found' });
    }

    if (req.user.role === 'EMPLOYER' && job.employerId !== req.user.id) {
      return res.status(403).json({ error: 'Unauthorized to delete this job' });
    }

    await prisma.job.delete({
      where: { id }
    });

    res.json({ message: 'Job deleted successfully' });
  } catch (error) {
    console.error('Delete job error:', error);
    res.status(500).json({ error: 'Failed to delete job' });
  }
};

// Get employer's jobs
exports.getEmployerJobs = async (req, res) => {
  try {
    const employerId = req.params.employerId ? parseInt(req.params.employerId) : req.user.id;
    const { isActive, page = 1, limit = 10 } = req.query;

    const where = { employerId };
    if (isActive !== undefined) where.isActive = isActive === 'true';

    const skip = (parseInt(page) - 1) * parseInt(limit);
    const take = parseInt(limit);

    const [jobs, total] = await Promise.all([
      prisma.job.findMany({
        where,
        skip,
        take,
        orderBy: { createdAt: 'desc' },
        include: {
          _count: {
            select: {
              applications: true,
              savedBy: true
            }
          }
        }
      }),
      prisma.job.count({ where })
    ]);

    res.json({
      jobs,
      pagination: {
        total,
        page: parseInt(page),
        limit: parseInt(limit),
        totalPages: Math.ceil(total / parseInt(limit))
      }
    });
  } catch (error) {
    console.error('Get employer jobs error:', error);
    res.status(500).json({ error: 'Failed to get employer jobs' });
  }
};

// Save/Unsave job (Candidate only)
exports.toggleSaveJob = async (req, res) => {
  try {
    const jobId = parseInt(req.params.id);

    // Check if job exists
    const job = await prisma.job.findUnique({
      where: { id: jobId }
    });

    if (!job) {
      return res.status(404).json({ error: 'Job not found' });
    }

    // Check if already saved
    const existingSave = await prisma.savedJob.findUnique({
      where: {
        userId_jobId: {
          userId: req.user.id,
          jobId
        }
      }
    });

    if (existingSave) {
      // Unsave
      await prisma.savedJob.delete({
        where: { id: existingSave.id }
      });

      res.json({ message: 'Job unsaved successfully', saved: false });
    } else {
      // Save
      await prisma.savedJob.create({
        data: {
          userId: req.user.id,
          jobId
        }
      });

      res.json({ message: 'Job saved successfully', saved: true });
    }
  } catch (error) {
    console.error('Toggle save job error:', error);
    res.status(500).json({ error: 'Failed to save/unsave job' });
  }
};

// Get saved jobs (Candidate only)
exports.getSavedJobs = async (req, res) => {
  try {
    const { page = 1, limit = 10 } = req.query;

    const skip = (parseInt(page) - 1) * parseInt(limit);
    const take = parseInt(limit);

    const [savedJobs, total] = await Promise.all([
      prisma.savedJob.findMany({
        where: { userId: req.user.id },
        skip,
        take,
        orderBy: { savedAt: 'desc' },
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
              },
              _count: {
                select: {
                  applications: true
                }
              }
            }
          }
        }
      }),
      prisma.savedJob.count({
        where: { userId: req.user.id }
      })
    ]);

    res.json({
      savedJobs: savedJobs.map(s => ({
        ...s.job,
        savedAt: s.savedAt
      })),
      pagination: {
        total,
        page: parseInt(page),
        limit: parseInt(limit),
        totalPages: Math.ceil(total / parseInt(limit))
      }
    });
  } catch (error) {
    console.error('Get saved jobs error:', error);
    res.status(500).json({ error: 'Failed to get saved jobs' });
  }
};

// Get job statistics (Admin)
exports.getJobStats = async (req, res) => {
  try {
    const [totalJobs, activeJobs, jobsByType, jobsByEmployer, recentJobs] = await Promise.all([
      prisma.job.count(),
      prisma.job.count({ where: { isActive: true } }),
      prisma.job.groupBy({
        by: ['jobType'],
        _count: true
      }),
      prisma.job.groupBy({
        by: ['employerId'],
        _count: true,
        orderBy: { _count: { employerId: 'desc' } },
        take: 5
      }),
      prisma.job.findMany({
        take: 10,
        orderBy: { createdAt: 'desc' },
        select: {
          id: true,
          title: true,
          company: true,
          createdAt: true,
          _count: {
            select: { applications: true }
          }
        }
      })
    ]);

    res.json({
      totalJobs,
      activeJobs,
      inactiveJobs: totalJobs - activeJobs,
      jobsByType,
      topEmployers: jobsByEmployer,
      recentJobs
    });
  } catch (error) {
    console.error('Get job stats error:', error);
    res.status(500).json({ error: 'Failed to get job statistics' });
  }
};
