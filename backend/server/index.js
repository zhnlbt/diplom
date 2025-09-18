// server/index.js
const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const { PrismaClient } = require('@prisma/client');

// Load environment variables
dotenv.config();

// Import routes
const userRoutes = require('../routes/userRoutes');
const jobRoutes = require('../routes/jobRoutes');
const applicationRoutes = require('../routes/applicationRoutes');

// Initialize Express app
const app = express();
const PORT = process.env.PORT || 5000;

// Initialize Prisma Client
const prisma = new PrismaClient();

// Middleware
app.use(cors({
  origin: process.env.NODE_ENV === 'production' 
    ? process.env.FRONTEND_URL 
    : ['http://localhost:3000', 'http://localhost:5173'], // Support for React and Vite
  credentials: true
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Request logging middleware (development only)
if (process.env.NODE_ENV === 'development') {
  app.use((req, res, next) => {
    console.log(`${new Date().toISOString()} - ${req.method} ${req.path}`);
    next();
  });
}

// Health check endpoint
app.get('/health', async (req, res) => {
  try {
    // Test database connection
    await prisma.$queryRaw`SELECT 1`;
    res.json({ 
      status: 'healthy',
      timestamp: new Date().toISOString(),
      environment: process.env.NODE_ENV,
      database: 'connected'
    });
  } catch (error) {
    res.status(500).json({ 
      status: 'unhealthy',
      error: 'Database connection failed'
    });
  }
});

// API Routes
app.use('/api/users', userRoutes);
app.use('/api/jobs', jobRoutes);
app.use('/api/applications', applicationRoutes);

// Welcome route
app.get('/', (req, res) => {
  res.json({
    message: 'Job Portal API',
    version: '1.0.0',
    endpoints: {
      health: '/health',
      users: '/api/users',
      jobs: '/api/jobs',
      applications: '/api/applications'
    },
    documentation: {
      register: 'POST /api/users/register',
      login: 'POST /api/users/login',
      jobs: 'GET /api/jobs',
      apply: 'POST /api/applications/jobs/:jobId/apply'
    }
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    error: 'Not Found',
    message: `Cannot ${req.method} ${req.originalUrl}`,
    timestamp: new Date().toISOString()
  });
});

// Global error handler
app.use((err, req, res, next) => {
  console.error('Error:', err);
  
  // Prisma error handling
  if (err.code === 'P2002') {
    return res.status(400).json({
      error: 'Duplicate entry',
      message: 'A record with this value already exists',
      field: err.meta?.target
    });
  }
  
  if (err.code === 'P2025') {
    return res.status(404).json({
      error: 'Not found',
      message: 'The requested record was not found'
    });
  }
  
  // JWT errors
  if (err.name === 'JsonWebTokenError') {
    return res.status(401).json({
      error: 'Invalid token',
      message: 'The provided token is invalid'
    });
  }
  
  if (err.name === 'TokenExpiredError') {
    return res.status(401).json({
      error: 'Token expired',
      message: 'Your session has expired. Please login again'
    });
  }
  
  // Default error response
  res.status(err.status || 500).json({
    error: err.message || 'Internal Server Error',
    message: process.env.NODE_ENV === 'development' 
      ? err.stack 
      : 'Something went wrong!',
    timestamp: new Date().toISOString()
  });
});

// Graceful shutdown
process.on('SIGINT', async () => {
  console.log('\n🔴 SIGINT signal received: closing HTTP server');
  await prisma.$disconnect();
  process.exit(0);
});

process.on('SIGTERM', async () => {
  console.log('🔴 SIGTERM signal received: closing HTTP server');
  await prisma.$disconnect();
  process.exit(0);
});

// Start server
const server = app.listen(PORT, () => {
  console.log(`
╔════════════════════════════════════════╗
║                                        ║
║     🚀 Job Portal API Server           ║
║     Running on port ${PORT}               ║
║     Environment: ${process.env.NODE_ENV || 'development'}          ║
║                                        ║
║     Ready to accept connections!       ║
║                                        ║
╚════════════════════════════════════════╝
  `);
  
  if (process.env.NODE_ENV === 'development') {
    console.log('\n📝 Available endpoints:');
    console.log('   Health Check: http://localhost:' + PORT + '/health');
    console.log('   API Docs: http://localhost:' + PORT + '/');
    console.log('\n🔐 Test credentials:');
    console.log('   Admin: admin@jobportal.com / admin123');
    console.log('   Employer: techcorp@example.com / employer123');
    console.log('   Candidate: john.developer@example.com / candidate123\n');
  }
});

module.exports = server;
