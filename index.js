// ===== index.js (Enhanced) =====
const express = require('express');
const cors = require('cors');
const cron = require('node-cron');
const authRoutes = require('./routes/auth');
const guildRoutes = require('./routes/guilds');
const { connectDB, cleanupExpiredData } = require('./models');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// CORS Configuration
app.use(cors({
  origin: process.env.FRONTEND_URL || '*',
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// Middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Trust proxy for accurate IP addresses
app.set('trust proxy', true);

// Request logging middleware (development only)
if (process.env.NODE_ENV === 'development') {
  app.use((req, res, next) => {
    console.log(`${new Date().toISOString()} - ${req.method} ${req.path}`);
    next();
  });
}

// Health check endpoint
app.get('/', (req, res) => {
  res.json({ 
    status: 'OK', 
    message: 'Discord OAuth2 JWT Backend with Token Refresh is running!',
    timestamp: new Date().toISOString(),
    version: '2.0.0',
    features: [
      'Discord OAuth2 Authentication',
      'JWT Session Management', 
      'Automatic Token Refresh',
      'MySQL/MariaDB Integration',
      'Session Management',
      'Guild Caching'
    ]
  });
});

// API health check
app.get('/api/health', async (req, res) => {
  try {
    // Check database connection
    const { sequelize } = require('./models');
    await sequelize.authenticate();
    
    res.json({
      status: 'healthy',
      timestamp: new Date().toISOString(),
      database: 'connected',
      environment: process.env.NODE_ENV || 'development'
    });
  } catch (error) {
    console.error('Health check failed:', error);
    res.status(500).json({
      status: 'unhealthy',
      timestamp: new Date().toISOString(),
      database: 'disconnected',
      error: error.message
    });
  }
});

// Routes
app.use('/api/auth', authRoutes);
app.use('/api/guilds', guildRoutes);

// Rate limiting middleware (simple implementation)
const rateLimit = require('express-rate-limit');
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: {
    error: 'Too many requests from this IP, please try again later.'
  },
  standardHeaders: true,
  legacyHeaders: false,
});

// Apply rate limiting to all API routes
app.use('/api', limiter);

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  
  // Don't leak error details in production
  const isDevelopment = process.env.NODE_ENV === 'development';
  
  res.status(err.status || 500).json({ 
    error: 'Internal server error',
    ...(isDevelopment && { details: err.message, stack: err.stack })
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({ 
    error: 'Route not found',
    path: req.originalUrl,
    method: req.method
  });
});



// Setup cleanup cron job (runs every hour)
if (process.env.ENABLE_CLEANUP !== 'false') {
  cron.schedule('0 * * * *', async () => {
    console.log('🧹 Running scheduled cleanup...');
    try {
      await cleanupExpiredData();
    } catch (error) {
      console.error('❌ Cleanup failed:', error);
    }
  });
  console.log('⏰ Cleanup cron job scheduled (every hour)');
}

// Initialize database and start server
const startServer = async () => {
  try {
    // Connect to database
    const dbConnected = await connectDB();
    if (!dbConnected) {
      console.error('❌ Failed to connect to database. Exiting...');
      process.exit(1);
    }

    // Run initial cleanup
    if (process.env.ENABLE_CLEANUP !== 'false') {
      console.log('🧹 Running initial cleanup...');
      await cleanupExpiredData();
    }

    // Start server
    const server = app.listen(PORT, '0.0.0.0', () => {
      console.log('\n' + '='.repeat(60));
      console.log('🚀 Discord OAuth2 Backend Server Started!');
      console.log('='.repeat(60));
      console.log(`📍 Server running on: ${process.env.HOST || `http://localhost:${PORT}`}`);
      console.log(`🔐 Auth endpoint: ${process.env.HOST || `http://localhost:${PORT}`}/api/auth/discord`);
      console.log(`🏥 Health check: ${process.env.HOST || `http://localhost:${PORT}`}/api/health`);
      console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
      console.log(`🗄️  Database: ${process.env.DB_HOST || 'localhost'}:${process.env.DB_PORT || 3306}`);
      console.log(`🧹 Auto-cleanup: ${process.env.ENABLE_CLEANUP !== 'false' ? 'enabled' : 'disabled'}`);
      console.log('='.repeat(60) + '\n');
    });


    return server;

  } catch (error) {
    console.error('❌ Failed to start server:', error);
    process.exit(1);
  }
};

// Start the server
const server = startServer();

module.exports = app;