// const express = require('express');
// const mongoose = require('mongoose');
// const bcrypt = require('bcryptjs');
// const jwt = require('jsonwebtoken');
// const cors = require('cors');
// const helmet = require('helmet');
// const rateLimit = require('express-rate-limit');
// require('dotenv').config();

// const app = express();


// app.use(helmet());
// app.use(cors({
//   origin: process.env.CLIENT_URL || 'http://localhost:3000',
//   credentials: true
// }));


// const limiter = rateLimit({
//   windowMs: 15 * 60 * 1000, 
//   max: 100, 
//   message: 'Too many requests from this IP, please try again later.'
// });
// app.use(limiter);


// const authLimiter = rateLimit({
//   windowMs: 15 * 60 * 1000, 
//   max: 5, 
//   message: 'Too many authentication attempts, please try again later.'
// });


// app.use(express.json({ limit: '10mb' }));
// app.use(express.urlencoded({ extended: true }));


// mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/myjob', {
//   useNewUrlParser: true,
//   useUnifiedTopology: true,
// })
// .then(() => console.log('✅ MongoDB Connected Successfully'))
// .catch(err => {
//   console.error('❌ MongoDB Connection Error:', err.message);
//   process.exit(1);
// });


// const userSchema = new mongoose.Schema({
//   name: {
//     type: String,
//     required: [true, 'Name is required'],
//     trim: true,
//     minlength: [2, 'Name must be at least 2 characters'],
//     maxlength: [50, 'Name cannot exceed 50 characters']
//   },
//   email: {
//     type: String,
//     required: [true, 'Email is required'],
//     unique: true,
//     lowercase: true,
//     match: [/^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/, 'Please enter a valid email']
//   },
//   password: {
//     type: String,
//     required: [true, 'Password is required'],
//     minlength: [6, 'Password must be at least 6 characters']
//   },
//   role: {
//     type: String,
//     enum: ['candidate', 'employer', 'admin'],
//     default: 'candidate'
//   },
//   isEmailVerified: {
//     type: Boolean,
//     default: false
//   },
//   profilePicture: {
//     type: String,
//     default: ''
//   },
//   refreshTokens: [{
//     token: String,
//     createdAt: {
//       type: Date,
//       default: Date.now,
//       expires: 604800 
//     }
//   }]
// }, {
//   timestamps: true
// });


// userSchema.pre('save', async function(next) {
//   if (!this.isModified('password')) return next();
  
//   try {
//     const salt = await bcrypt.genSalt(12);
//     this.password = await bcrypt.hash(this.password, salt);
//     next();
//   } catch (error) {
//     next(error);
//   }
// });


// userSchema.methods.comparePassword = async function(candidatePassword) {
//   return await bcrypt.compare(candidatePassword, this.password);
// };


// userSchema.methods.toJSON = function() {
//   const userObject = this.toObject();
//   delete userObject.password;
//   delete userObject.refreshTokens;
//   return userObject;
// };

// const User = mongoose.model('User', userSchema);


// const generateAccessToken = (userId) => {
//   return jwt.sign(
//     { userId }, 
//     process.env.JWT_SECRET || 'fallback-secret-key',
//     { expiresIn: process.env.JWT_EXPIRE || '15m' }
//   );
// };

// const generateRefreshToken = (userId) => {
//   return jwt.sign(
//     { userId, type: 'refresh' }, 
//     process.env.JWT_REFRESH_SECRET || 'fallback-refresh-secret',
//     { expiresIn: process.env.JWT_REFRESH_EXPIRE || '7d' }
//   );
// };


// const authenticateToken = async (req, res, next) => {
//   try {
//     const authHeader = req.headers['authorization'];
//     const token = authHeader && authHeader.split(' ')[1]; 

//     if (!token) {
//       return res.status(401).json({
//         success: false,
//         message: 'Access token required'
//       });
//     }

//     const decoded = jwt.verify(token, process.env.JWT_SECRET || 'fallback-secret-key');
//     const user = await User.findById(decoded.userId);

//     if (!user) {
//       return res.status(401).json({
//         success: false,
//         message: 'User not found'
//       });
//     }

//     req.user = user;
//     next();
//   } catch (error) {
//     if (error.name === 'TokenExpiredError') {
//       return res.status(401).json({
//         success: false,
//         message: 'Access token expired'
//       });
//     }
    
//     return res.status(403).json({
//       success: false,
//       message: 'Invalid token'
//     });
//   }
// };


// const errorHandler = (err, req, res, next) => {
//   console.error(err.stack);

  
//   if (err.name === 'ValidationError') {
//     const errors = Object.values(err.errors).map(e => e.message);
//     return res.status(400).json({
//       success: false,
//       message: 'Validation Error',
//       errors
//     });
//   }

  
//   if (err.code === 11000) {
//     const field = Object.keys(err.keyValue)[0];
//     return res.status(400).json({
//       success: false,
//       message: `${field} already exists`
//     });
//   }

  
//   if (err.name === 'JsonWebTokenError') {
//     return res.status(401).json({
//       success: false,
//       message: 'Invalid token'
//     });
//   }

  
//   res.status(500).json({
//     success: false,
//     message: process.env.NODE_ENV === 'development' ? err.message : 'Internal server error'
//   });
// };




// app.get('/api/health', (req, res) => {
//   res.json({
//     success: true,
//     message: 'Server is running',
//     timestamp: new Date().toISOString()
//   });
// });


// app.post('/api/auth/register', authLimiter, async (req, res) => {
//   try {
//     const { name, email, password, role } = req.body;

    
//     if (!name || !email || !password) {
//       return res.status(400).json({
//         success: false,
//         message: 'All fields are required'
//       });
//     }

//     if (password.length < 6) {
//       return res.status(400).json({
//         success: false,
//         message: 'Password must be at least 6 characters'
//       });
//     }

    
//     const existingUser = await User.findOne({ email });
//     if (existingUser) {
//       return res.status(400).json({
//         success: false,
//         message: 'User already exists with this email'
//       });
//     }

    
//     const user = new User({
//       name: name.trim(),
//       email: email.toLowerCase().trim(),
//       password,
//       role: role || 'candidate'
//     });

//     await user.save();

    
//     const accessToken = generateAccessToken(user._id);
//     const refreshToken = generateRefreshToken(user._id);

    
//     user.refreshTokens.push({ token: refreshToken });
//     await user.save();

//     res.status(201).json({
//       success: true,
//       message: 'User registered successfully',
//       user,
//       token: accessToken,
//       refreshToken
//     });

//   } catch (error) {
//     console.error('Registration error:', error);
//     res.status(500).json({
//       success: false,
//       message: 'Error creating user',
//       error: process.env.NODE_ENV === 'development' ? error.message : undefined
//     });
//   }
// });


// app.post('/api/auth/login', authLimiter, async (req, res) => {
//   try {
//     const { email, password, rememberMe } = req.body;

    
//     if (!email || !password) {
//       return res.status(400).json({
//         success: false,
//         message: 'Email and password are required'
//       });
//     }

    
//     const user = await User.findOne({ email: email.toLowerCase().trim() });
//     if (!user) {
//       return res.status(401).json({
//         success: false,
//         message: 'Invalid credentials'
//       });
//     }

    
//     const isPasswordValid = await user.comparePassword(password);
//     if (!isPasswordValid) {
//       return res.status(401).json({
//         success: false,
//         message: 'Invalid credentials'
//       });
//     }

    
//     const accessToken = generateAccessToken(user._id);
//     const refreshToken = generateRefreshToken(user._id);

    
//     if (rememberMe) {
//       user.refreshTokens.push({ token: refreshToken });
//       await user.save();
//     }

//     res.json({
//       success: true,
//       message: 'Login successful',
//       user,
//       token: accessToken,
//       refreshToken: rememberMe ? refreshToken : undefined
//     });

//   } catch (error) {
//     console.error('Login error:', error);
//     res.status(500).json({
//       success: false,
//       message: 'Error logging in',
//       error: process.env.NODE_ENV === 'development' ? error.message : undefined
//     });
//   }
// });


// app.post('/api/auth/refresh', async (req, res) => {
//   try {
//     const authHeader = req.headers['authorization'];
//     const refreshToken = authHeader && authHeader.split(' ')[1];

//     if (!refreshToken) {
//       return res.status(401).json({
//         success: false,
//         message: 'Refresh token required'
//       });
//     }

    
//     const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET || 'fallback-refresh-secret');
    
//     if (decoded.type !== 'refresh') {
//       return res.status(403).json({
//         success: false,
//         message: 'Invalid token type'
//       });
//     }

    
//     const user = await User.findById(decoded.userId);
//     if (!user || !user.refreshTokens.some(rt => rt.token === refreshToken)) {
//       return res.status(403).json({
//         success: false,
//         message: 'Invalid refresh token'
//       });
//     }

    
//     const newAccessToken = generateAccessToken(user._id);

//     res.json({
//       success: true,
//       token: newAccessToken
//     });

//   } catch (error) {
//     console.error('Token refresh error:', error);
//     res.status(403).json({
//       success: false,
//       message: 'Invalid refresh token'
//     });
//   }
// });


// app.post('/api/auth/logout', authenticateToken, async (req, res) => {
//   try {
//     const authHeader = req.headers['authorization'];
//     const refreshToken = req.body.refreshToken;

    
//     if (refreshToken) {
//       await User.findByIdAndUpdate(
//         req.user._id,
//         { $pull: { refreshTokens: { token: refreshToken } } }
//       );
//     }

//     res.json({
//       success: true,
//       message: 'Logged out successfully'
//     });

//   } catch (error) {
//     console.error('Logout error:', error);
//     res.status(500).json({
//       success: false,
//       message: 'Error logging out'
//     });
//   }
// });


// app.get('/api/users/profile', authenticateToken, async (req, res) => {
//   try {
//     res.json({
//       success: true,
//       user: req.user
//     });
//   } catch (error) {
//     console.error('Profile fetch error:', error);
//     res.status(500).json({
//       success: false,
//       message: 'Error fetching profile'
//     });
//   }
// });


// app.put('/api/users/profile', authenticateToken, async (req, res) => {
//   try {
//     const { name, profilePicture } = req.body;
    
//     const updateData = {};
//     if (name) updateData.name = name.trim();
//     if (profilePicture) updateData.profilePicture = profilePicture;

//     const user = await User.findByIdAndUpdate(
//       req.user._id,
//       updateData,
//       { new: true, runValidators: true }
//     );

//     res.json({
//       success: true,
//       message: 'Profile updated successfully',
//       user
//     });

//   } catch (error) {
//     console.error('Profile update error:', error);
//     res.status(500).json({
//       success: false,
//       message: 'Error updating profile',
//       error: process.env.NODE_ENV === 'development' ? error.message : undefined
//     });
//   }
// });


// app.put('/api/users/change-password', authenticateToken, async (req, res) => {
//   try {
//     const { currentPassword, newPassword } = req.body;

//     if (!currentPassword || !newPassword) {
//       return res.status(400).json({
//         success: false,
//         message: 'Current password and new password are required'
//       });
//     }

//     if (newPassword.length < 6) {
//       return res.status(400).json({
//         success: false,
//         message: 'New password must be at least 6 characters'
//       });
//     }

    
//     const user = await User.findById(req.user._id);
//     const isCurrentPasswordValid = await user.comparePassword(currentPassword);

//     if (!isCurrentPasswordValid) {
//       return res.status(400).json({
//         success: false,
//         message: 'Current password is incorrect'
//       });
//     }

    
//     user.password = newPassword;
//     await user.save();

//     res.json({
//       success: true,
//       message: 'Password changed successfully'
//     });

//   } catch (error) {
//     console.error('Password change error:', error);
//     res.status(500).json({
//       success: false,
//       message: 'Error changing password'
//     });
//   }
// });


// app.get('/api/users', authenticateToken, async (req, res) => {
//   try {
//     if (req.user.role !== 'admin') {
//       return res.status(403).json({
//         success: false,
//         message: 'Access denied. Admin role required.'
//       });
//     }

//     const page = parseInt(req.query.page) || 1;
//     const limit = parseInt(req.query.limit) || 10;
//     const skip = (page - 1) * limit;

//     const users = await User.find({})
//       .skip(skip)
//       .limit(limit)
//       .sort({ createdAt: -1 });

//     const total = await User.countDocuments();

//     res.json({
//       success: true,
//       users,
//       pagination: {
//         current: page,
//         total: Math.ceil(total / limit),
//         count: users.length,
//         totalUsers: total
//       }
//     });

//   } catch (error) {
//     console.error('Users fetch error:', error);
//     res.status(500).json({
//       success: false,
//       message: 'Error fetching users'
//     });
//   }
// });


// app.use('*', (req, res) => {
//   res.status(404).json({
//     success: false,
//     message: 'Route not found'
//   });
// });


// app.use(errorHandler);


// const PORT = process.env.PORT || 5000;
// app.listen(PORT, () => {
//   console.log(`🚀 Server running on port ${PORT}`);
//   console.log(`📍 Environment: ${process.env.NODE_ENV || 'development'}`);
//   console.log(`🌐 API Base URL: http://localhost:${PORT}/api`);
// });


// process.on('unhandledRejection', (err, promise) => {
//   console.error('Unhandled Promise Rejection:', err.message);
//   process.exit(1);
// });


// process.on('uncaughtException', (err) => {
//   console.error('Uncaught Exception:', err.message);
//   process.exit(1);
// });

// module.exports = app;


// // const S = process.env.PORT || 3000;
// // server.listen(PORT, "0.0.0.0", () => {
// //   console.log(`JSON Server with Auth running on port ${PORT}`);
// //   console.log("Available auth endpoints:");
// //   console.log("POST /auth/signup - Create new user");
// //   console.log("POST /auth/login - Login user");
// //   console.log("GET /auth/me - Get current user info (requires token)");
// //   console.log("API endpoints are available under /api/ prefix");
// // });



import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { PrismaClient } from '@prisma/client';
import multer from 'multer';
import path from 'path';
import { fileURLToPath } from 'url';
import fs from 'fs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const prisma = new PrismaClient();
const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

// Middleware
app.use(helmet());
app.use(cors());
app.use(express.json());
app.use(express.static('uploads'));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});
app.use(limiter);

// File upload configuration
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = 'uploads/';
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true });
    }
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
  }
});

const upload = multer({ 
  storage: storage,
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB limit
  },
  fileFilter: (req, file, cb) => {
    const allowedTypes = /jpeg|jpg|png|pdf|doc|docx/;
    const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = allowedTypes.test(file.mimetype);
    
    if (mimetype && extname) {
      return cb(null, true);
    } else {
      cb(new Error('Only images and documents are allowed'));
    }
  }
});

// Auth middleware
const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await prisma.user.findUnique({
      where: { id: decoded.userId },
      include: {
        employer: true,
        candidate: true
      }
    });
    
    if (!user) {
      return res.status(401).json({ error: 'Invalid token' });
    }
    
    req.user = user;
    next();
  } catch (error) {
    return res.status(403).json({ error: 'Invalid token' });
  }
};

// Helper function to create notifications
const createNotification = async (userId, title, message, type) => {
  await prisma.notification.create({
    data: {
      userId,
      title,
      message,
      type
    }
  });
};

// ============ AUTH ROUTES ============

// Register
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password, firstName, lastName, phone, userType } = req.body;

    // Check if user exists
    const existingUser = await prisma.user.findUnique({ where: { email } });
    if (existingUser) {
      return res.status(400).json({ error: 'User already exists' });
    }

    // Hash password
    const passwordHash = await bcrypt.hash(password, 10);

    // Create user
    const user = await prisma.user.create({
      data: {
        email,
        passwordHash,
        firstName,
        lastName,
        phone,
        userType
      }
    });

    // Create profile based on user type
    if (userType === 'EMPLOYER') {
      await prisma.employer.create({
        data: {
          userId: user.id,
          companyName: firstName || 'Unnamed Company'
        }
      });
    } else {
      await prisma.candidate.create({
        data: {
          userId: user.id
        }
      });
    }

    // Generate token
    const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '7d' });

    res.status(201).json({
      message: 'User created successfully',
      token,
      user: {
        id: user.id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        userType: user.userType
      }
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Find user
    const user = await prisma.user.findUnique({
      where: { email },
      include: {
        employer: true,
        candidate: true
      }
    });

    if (!user || !await bcrypt.compare(password, user.passwordHash)) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Generate token
    const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '7d' });

    res.json({
      message: 'Login successful',
      token,
      user: {
        id: user.id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        userType: user.userType,
        profile: user.employer || user.candidate
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get current user
app.get('/api/auth/me', authenticateToken, async (req, res) => {
  res.json({
    user: {
      id: req.user.id,
      email: req.user.email,
      firstName: req.user.firstName,
      lastName: req.user.lastName,
      userType: req.user.userType,
      profile: req.user.employer || req.user.candidate
    }
  });
});

// ============ USER PROFILE ROUTES ============

// Update employer profile
app.put('/api/profile/employer', authenticateToken, upload.single('logo'), async (req, res) => {
  try {
    if (req.user.userType !== 'EMPLOYER') {
      return res.status(403).json({ error: 'Access denied' });
    }

    const { companyName, companyDescription, industry, companySize } = req.body;
    const updateData = {
      companyName,
      companyDescription,
      industry,
      companySize
    };

    if (req.file) {
      updateData.companyLogo = req.file.filename;
    }

    const employer = await prisma.employer.update({
      where: { userId: req.user.id },
      data: updateData
    });

    res.json({ message: 'Profile updated successfully', employer });
  } catch (error) {
    console.error('Profile update error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Update candidate profile
app.put('/api/profile/candidate', authenticateToken, upload.fields([
  { name: 'photo', maxCount: 1 },
  { name: 'resume', maxCount: 1 }
]), async (req, res) => {
  try {
    if (req.user.userType !== 'CANDIDATE') {
      return res.status(403).json({ error: 'Access denied' });
    }

    const { bio, location, skills, salaryExpectation } = req.body;
    const updateData = {
      bio,
      location,
      skills,
      salaryExpectation: salaryExpectation ? parseInt(salaryExpectation) : null
    };

    if (req.files) {
      if (req.files.photo) {
        updateData.profilePhoto = req.files.photo[0].filename;
      }
      if (req.files.resume) {
        updateData.resumeUrl = req.files.resume[0].filename;
      }
    }

    const candidate = await prisma.candidate.update({
      where: { userId: req.user.id },
      data: updateData
    });

    res.json({ message: 'Profile updated successfully', candidate });
  } catch (error) {
    console.error('Profile update error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ============ JOB ROUTES ============

// Get all jobs
app.get('/api/jobs', async (req, res) => {
  try {
    const { page = 1, limit = 10, search, location, employment_type } = req.query;
    const skip = (page - 1) * limit;

    const where = {
      status: 'ACTIVE',
      ...(search && {
        OR: [
          { title: { contains: search, mode: 'insensitive' } },
          { description: { contains: search, mode: 'insensitive' } }
        ]
      }),
      ...(location && { location: { contains: location, mode: 'insensitive' } }),
      ...(employment_type && { employmentType: employment_type })
    };

    const jobs = await prisma.job.findMany({
      where,
      include: {
        employer: {
          include: {
            user: {
              select: { firstName: true, lastName: true }
            }
          }
        },
        _count: {
          select: { applications: true }
        }
      },
      orderBy: { postedDate: 'desc' },
      skip: parseInt(skip),
      take: parseInt(limit)
    });

    const total = await prisma.job.count({ where });

    res.json({
      jobs,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / limit)
      }
    });
  } catch (error) {
    console.error('Get jobs error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get single job
app.get('/api/jobs/:id', async (req, res) => {
  try {
    const job = await prisma.job.findUnique({
      where: { id: parseInt(req.params.id) },
      include: {
        employer: {
          include: {
            user: {
              select: { firstName: true, lastName: true }
            }
          }
        },
        _count: {
          select: { applications: true }
        }
      }
    });

    if (!job) {
      return res.status(404).json({ error: 'Job not found' });
    }

    res.json(job);
  } catch (error) {
    console.error('Get job error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Create job (employer only)
app.post('/api/jobs', authenticateToken, async (req, res) => {
  try {
    if (req.user.userType !== 'EMPLOYER') {
      return res.status(403).json({ error: 'Only employers can create jobs' });
    }

    const {
      title,
      description,
      location,
      employmentType,
      salaryMin,
      salaryMax
    } = req.body;

    const job = await prisma.job.create({
      data: {
        employerId: req.user.employer.id,
        title,
        description,
        location,
        employmentType,
        salaryMin: salaryMin ? parseFloat(salaryMin) : null,
        salaryMax: salaryMax ? parseFloat(salaryMax) : null
      },
      include: {
        employer: {
          include: {
            user: {
              select: { firstName: true, lastName: true }
            }
          }
        }
      }
    });

    // Check for job alerts and notify candidates
    const jobAlerts = await prisma.jobAlert.findMany({
      where: {
        active: true,
        OR: [
          { keywords: { contains: title, mode: 'insensitive' } },
          { location: { contains: location, mode: 'insensitive' } }
        ]
      },
      include: { candidate: { include: { user: true } } }
    });

    for (const alert of jobAlerts) {
      await createNotification(
        alert.candidate.userId,
        'New Job Alert',
        `A new job "${title}" matches your preferences`,
        'JOB_DESCRIPTION'
      );
    }

    res.status(201).json({ message: 'Job created successfully', job });
  } catch (error) {
    console.error('Create job error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Update job (employer only)
app.put('/api/jobs/:id', authenticateToken, async (req, res) => {
  try {
    if (req.user.userType !== 'EMPLOYER') {
      return res.status(403).json({ error: 'Access denied' });
    }

    const jobId = parseInt(req.params.id);
    const job = await prisma.job.findUnique({
      where: { id: jobId },
      include: { employer: true }
    });

    if (!job || job.employer.userId !== req.user.id) {
      return res.status(404).json({ error: 'Job not found or access denied' });
    }

    const {
      title,
      description,
      location,
      employmentType,
      salaryMin,
      salaryMax,
      status
    } = req.body;

    const updatedJob = await prisma.job.update({
      where: { id: jobId },
      data: {
        title,
        description,
        location,
        employmentType,
        salaryMin: salaryMin ? parseFloat(salaryMin) : null,
        salaryMax: salaryMax ? parseFloat(salaryMax) : null,
        status
      }
    });

    res.json({ message: 'Job updated successfully', job: updatedJob });
  } catch (error) {
    console.error('Update job error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Delete job (employer only)
app.delete('/api/jobs/:id', authenticateToken, async (req, res) => {
  try {
    if (req.user.userType !== 'EMPLOYER') {
      return res.status(403).json({ error: 'Access denied' });
    }

    const jobId = parseInt(req.params.id);
    const job = await prisma.job.findUnique({
      where: { id: jobId },
      include: { employer: true }
    });

    if (!job || job.employer.userId !== req.user.id) {
      return res.status(404).json({ error: 'Job not found or access denied' });
    }

    await prisma.job.delete({ where: { id: jobId } });
    res.json({ message: 'Job deleted successfully' });
  } catch (error) {
    console.error('Delete job error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ============ APPLICATION ROUTES ============

// Apply to job (candidate only)
app.post('/api/jobs/:id/apply', authenticateToken, async (req, res) => {
  try {
    if (req.user.userType !== 'CANDIDATE') {
      return res.status(403).json({ error: 'Only candidates can apply to jobs' });
    }

    const jobId = parseInt(req.params.id);
    const { coverLetter } = req.body;

    const job = await prisma.job.findUnique({
      where: { id: jobId },
      include: { employer: { include: { user: true } } }
    });

    if (!job) {
      return res.status(404).json({ error: 'Job not found' });
    }

    const application = await prisma.application.create({
      data: {
        jobId,
        candidateId: req.user.candidate.id,
        coverLetter
      }
    });

    // Notify employer
    await createNotification(
      job.employer.userId,
      'New Application',
      `${req.user.firstName} ${req.user.lastName} applied to ${job.title}`,
      'APPLICATION_UPDATE'
    );

    res.status(201).json({ message: 'Application submitted successfully', application });
  } catch (error) {
    if (error.code === 'P2002') {
      return res.status(400).json({ error: 'You have already applied to this job' });
    }
    console.error('Apply to job error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get candidate's applications
app.get('/api/applications/my', authenticateToken, async (req, res) => {
  try {
    if (req.user.userType !== 'CANDIDATE') {
      return res.status(403).json({ error: 'Access denied' });
    }

    const applications = await prisma.application.findMany({
      where: { candidateId: req.user.candidate.id },
      include: {
        job: {
          include: {
            employer: {
              include: {
                user: { select: { firstName: true, lastName: true } }
              }
            }
          }
        }
      },
      orderBy: { appliedAt: 'desc' }
    });

    res.json(applications);
  } catch (error) {
    console.error('Get applications error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get job applications (employer only)
app.get('/api/jobs/:id/applications', authenticateToken, async (req, res) => {
  try {
    if (req.user.userType !== 'EMPLOYER') {
      return res.status(403).json({ error: 'Access denied' });
    }

    const jobId = parseInt(req.params.id);
    const job = await prisma.job.findUnique({
      where: { id: jobId },
      include: { employer: true }
    });

    if (!job || job.employer.userId !== req.user.id) {
      return res.status(404).json({ error: 'Job not found or access denied' });
    }

    const applications = await prisma.application.findMany({
      where: { jobId },
      include: {
        candidate: {
          include: {
            user: { select: { firstName: true, lastName: true, email: true } }
          }
        }
      },
      orderBy: { appliedAt: 'desc' }
    });

    res.json(applications);
  } catch (error) {
    console.error('Get job applications error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Update application status (employer only)
app.put('/api/applications/:id/status', authenticateToken, async (req, res) => {
  try {
    if (req.user.userType !== 'EMPLOYER') {
      return res.status(403).json({ error: 'Access denied' });
    }

    const applicationId = parseInt(req.params.id);
    const { status, employerNotes } = req.body;

    const application = await prisma.application.findUnique({
      where: { id: applicationId },
      include: {
        job: { include: { employer: true } },
        candidate: { include: { user: true } }
      }
    });

    if (!application || application.job.employer.userId !== req.user.id) {
      return res.status(404).json({ error: 'Application not found or access denied' });
    }

    const updatedApplication = await prisma.application.update({
      where: { id: applicationId },
      data: { status, employerNotes }
    });

    // Notify candidate about status change
    await createNotification(
      application.candidate.userId,
      'Application Update',
      `Your application for ${application.job.title} has been ${status.toLowerCase()}`,
      'APPLICATION_UPDATE'
    );

    res.json({ message: 'Application status updated', application: updatedApplication });
  } catch (error) {
    console.error('Update application status error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ============ FAVORITE JOBS ROUTES ============

// Add job to favorites (candidate only)
app.post('/api/jobs/:id/favorite', authenticateToken, async (req, res) => {
  try {
    if (req.user.userType !== 'CANDIDATE') {
      return res.status(403).json({ error: 'Only candidates can favorite jobs' });
    }

    const jobId = parseInt(req.params.id);

    const favorite = await prisma.favoriteJob.create({
      data: {
        candidateId: req.user.candidate.id,
        jobId
      }
    });

    res.status(201).json({ message: 'Job added to favorites', favorite });
  } catch (error) {
    if (error.code === 'P2002') {
      return res.status(400).json({ error: 'Job already in favorites' });
    }
    console.error('Add favorite error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Remove job from favorites (candidate only)
app.delete('/api/jobs/:id/favorite', authenticateToken, async (req, res) => {
  try {
    if (req.user.userType !== 'CANDIDATE') {
      return res.status(403).json({ error: 'Access denied' });
    }

    const jobId = parseInt(req.params.id);

    await prisma.favoriteJob.deleteMany({
      where: {
        candidateId: req.user.candidate.id,
        jobId
      }
    });

    res.json({ message: 'Job removed from favorites' });
  } catch (error) {
    console.error('Remove favorite error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get candidate's favorite jobs
app.get('/api/favorites', authenticateToken, async (req, res) => {
  try {
    if (req.user.userType !== 'CANDIDATE') {
      return res.status(403).json({ error: 'Access denied' });
    }

    const favorites = await prisma.favoriteJob.findMany({
      where: { candidateId: req.user.candidate.id },
      include: {
        job: {
          include: {
            employer: {
              include: {
                user: { select: { firstName: true, lastName: true } }
              }
            },
            _count: {
              select: { applications: true }
            }
          }
        }
      },
      orderBy: { favoritedAt: 'desc' }
    });

    res.json(favorites.map(fav => fav.job));
  } catch (error) {
    console.error('Get favorites error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ============ JOB ALERTS ROUTES ============

// Create job alert (candidate only)
app.post('/api/job-alerts', authenticateToken, async (req, res) => {
  try {
    if (req.user.userType !== 'CANDIDATE') {
      return res.status(403).json({ error: 'Only candidates can create job alerts' });
    }

    const { keywords, location } = req.body;

    const jobAlert = await prisma.jobAlert.create({
      data: {
        candidateId: req.user.candidate.id,
        keywords,
        location
      }
    });

    res.status(201).json({ message: 'Job alert created successfully', jobAlert });
  } catch (error) {
    console.error('Create job alert error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get candidate's job alerts
app.get('/api/job-alerts', authenticateToken, async (req, res) => {
  try {
    if (req.user.userType !== 'CANDIDATE') {
      return res.status(403).json({ error: 'Access denied' });
    }

    const jobAlerts = await prisma.jobAlert.findMany({
      where: { candidateId: req.user.candidate.id },
      orderBy: { createdAt: 'desc' }
    });

    res.json(jobAlerts);
  } catch (error) {
    console.error('Get job alerts error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Update job alert
app.put('/api/job-alerts/:id', authenticateToken, async (req, res) => {
  try {
    if (req.user.userType !== 'CANDIDATE') {
      return res.status(403).json({ error: 'Access denied' });
    }

    const alertId = parseInt(req.params.id);
    const { keywords, location, active } = req.body;

    const jobAlert = await prisma.jobAlert.findUnique({
      where: { id: alertId }
    });

    if (!jobAlert || jobAlert.candidateId !== req.user.candidate.id) {
      return res.status(404).json({ error: 'Job alert not found or access denied' });
    }

    const updatedAlert = await prisma.jobAlert.update({
      where: { id: alertId },
      data: { keywords, location, active }
    });

    res.json({ message: 'Job alert updated successfully', jobAlert: updatedAlert });
  } catch (error) {
    console.error('Update job alert error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Delete job alert
app.delete('/api/job-alerts/:id', authenticateToken, async (req, res) => {
  try {
    if (req.user.userType !== 'CANDIDATE') {
      return res.status(403).json({ error: 'Access denied' });
    }

    const alertId = parseInt(req.params.id);

    const jobAlert = await prisma.jobAlert.findUnique({
      where: { id: alertId }
    });

    if (!jobAlert || jobAlert.candidateId !== req.user.candidate.id) {
      return res.status(404).json({ error: 'Job alert not found or access denied' });
    }

    await prisma.jobAlert.delete({ where: { id: alertId } });
    res.json({ message: 'Job alert deleted successfully' });
  } catch (error) {
    console.error('Delete job alert error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ============ NOTIFICATIONS ROUTES ============

// Get user notifications
app.get('/api/notifications', authenticateToken, async (req, res) => {
  try {
    const notifications = await prisma.notification.findMany({
      where: { userId: req.user.id },
      orderBy: { createdAt: 'desc' },
      take: 50 // Limit to last 50 notifications
    });

    res.json(notifications);
  } catch (error) {
    console.error('Get notifications error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Mark notification as read
app.put('/api/notifications/:id/read', authenticateToken, async (req, res) => {
  try {
    const notificationId = parseInt(req.params.id);

    const notification = await prisma.notification.findUnique({
      where: { id: notificationId }
    });

    if (!notification || notification.userId !== req.user.id) {
      return res.status(404).json({ error: 'Notification not found or access denied' });
    }

    await prisma.notification.update({
      where: { id: notificationId },
      data: { read: true }
    });

    res.json({ message: 'Notification marked as read' });
  } catch (error) {
    console.error('Mark notification read error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Mark all notifications as read
app.put('/api/notifications/read-all', authenticateToken, async (req, res) => {
  try {
    await prisma.notification.updateMany({
      where: { userId: req.user.id, read: false },
      data: { read: true }
    });

    res.json({ message: 'All notifications marked as read' });
  } catch (error) {
    console.error('Mark all notifications read error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ============ DASHBOARD ROUTES ============

// Get employer dashboard stats
app.get('/api/dashboard/employer', authenticateToken, async (req, res) => {
  try {
    if (req.user.userType !== 'EMPLOYER') {
      return res.status(403).json({ error: 'Access denied' });
    }

    const employerId = req.user.employer.id;

    const [totalJobs, activeJobs, totalApplications, recentApplications] = await Promise.all([
      prisma.job.count({ where: { employerId } }),
      prisma.job.count({ where: { employerId, status: 'ACTIVE' } }),
      prisma.application.count({
        where: { job: { employerId } }
      }),
      prisma.application.findMany({
        where: { job: { employerId } },
        include: {
          candidate: {
            include: {
              user: { select: { firstName: true, lastName: true } }
            }
          },
          job: { select: { title: true } }
        },
        orderBy: { appliedAt: 'desc' },
        take: 5
      })
    ]);

    res.json({
      stats: {
        totalJobs,
        activeJobs,
        totalApplications
      },
      recentApplications
    });
  } catch (error) {
    console.error('Employer dashboard error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get candidate dashboard stats
app.get('/api/dashboard/candidate', authenticateToken, async (req, res) => {
  try {
    if (req.user.userType !== 'CANDIDATE') {
      return res.status(403).json({ error: 'Access denied' });
    }

    const candidateId = req.user.candidate.id;

    const [totalApplications, pendingApplications, favoriteJobs, jobAlerts] = await Promise.all([
      prisma.application.count({ where: { candidateId } }),
      prisma.application.count({ where: { candidateId, status: 'PENDING' } }),
      prisma.favoriteJob.count({ where: { candidateId } }),
      prisma.jobAlert.count({ where: { candidateId, active: true } })
    ]);

    const recentApplications = await prisma.application.findMany({
      where: { candidateId },
      include: {
        job: {
          include: {
            employer: {
              include: {
                user: { select: { firstName: true, lastName: true } }
              }
            }
          }
        }
      },
      orderBy: { appliedAt: 'desc' },
      take: 5
    });

    res.json({
      stats: {
        totalApplications,
        pendingApplications,
        favoriteJobs,
        jobAlerts
      },
      recentApplications
    });
  } catch (error) {
    console.error('Candidate dashboard error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ============ SEARCH ROUTES ============

// Advanced job search
app.get('/api/search/jobs', async (req, res) => {
  try {
    const {
      q,
      location,
      employment_type,
      salary_min,
      salary_max,
      company,
      page = 1,
      limit = 10
    } = req.query;

    const skip = (page - 1) * limit;

    const where = {
      status: 'ACTIVE',
      ...(q && {
        OR: [
          { title: { contains: q, mode: 'insensitive' } },
          { description: { contains: q, mode: 'insensitive' } }
        ]
      }),
      ...(location && { location: { contains: location, mode: 'insensitive' } }),
      ...(employment_type && { employmentType: employment_type }),
      ...(salary_min && { salaryMax: { gte: parseFloat(salary_min) } }),
      ...(salary_max && { salaryMin: { lte: parseFloat(salary_max) } }),
      ...(company && {
        employer: {
          companyName: { contains: company, mode: 'insensitive' }
        }
      })
    };

    const jobs = await prisma.job.findMany({
      where,
      include: {
        employer: {
          include: {
            user: { select: { firstName: true, lastName: true } }
          }
        },
        _count: {
          select: { applications: true }
        }
      },
      orderBy: { postedDate: 'desc' },
      skip: parseInt(skip),
      take: parseInt(limit)
    });

    const total = await prisma.job.count({ where });

    res.json({
      jobs,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / limit)
      }
    });
  } catch (error) {
    console.error('Search jobs error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ============ ERROR HANDLING ============

// Global error handler
app.use((err, req, res, next) => {
  console.error('Global error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

// ============ SERVER START ============

const startServer = async () => {
  try {
    await prisma.$connect();
    console.log('Connected to database');
    
    app.listen(PORT, () => {
      console.log(`Server running on port ${PORT}`);
      console.log(`API Base URL: http://localhost:${PORT}/api`);
    });
  } catch (error) {
    console.error('Failed to start server:', error);
    process.exit(1);
  }
};

// Graceful shutdown
process.on('SIGTERM', async () => {
  console.log('SIGTERM received, shutting down gracefully');
  await prisma.$disconnect();
  process.exit(0);
});

process.on('SIGINT', async () => {
  console.log('SIGINT received, shutting down gracefully');
  await prisma.$disconnect();
  process.exit(0);
});

startServer();