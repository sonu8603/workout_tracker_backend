const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const mongoSanitize = require('express-mongo-sanitize');
const xss = require('xss-clean');
const hpp = require('hpp');
const compression = require('compression');
const dotenv = require('dotenv');
const connectDB = require('./config/db');

// Load environment variables
dotenv.config();

// Validate critical environment variables
const requiredEnvVars = ['MONGODB_URI', 'JWT_SECRET'];
const missingEnvVars = requiredEnvVars.filter(varName => !process.env[varName]);

if (missingEnvVars.length > 0) {
  console.error('❌ CRITICAL: Missing required environment variables:');
  missingEnvVars.forEach(varName => console.error(`   - ${varName}`));
  process.exit(1);
}

const app = express();

// Connect to MongoDB
connectDB();

// Trust proxy
app.set('trust proxy', 1);

// ==================== SECURITY MIDDLEWARE ====================

// Helmet
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
    },
  },
  crossOriginEmbedderPolicy: false,
}));

// CORS
const corsOptions = {
  origin: function (origin, callback) {
    // Allow requests with no origin (mobile apps, Postman, etc.)
    if (!origin) {
      return callback(null, true);
    }
    
    // Check if ALLOWED_ORIGINS is set to '*' (allow all)
    if (process.env.ALLOWED_ORIGINS === '*') {
      return callback(null, true);
    }
    
    // Parse allowed origins from environment variable
    const allowedOrigins = process.env.ALLOWED_ORIGINS 
      ? process.env.ALLOWED_ORIGINS.split(',').map(o => o.trim())
      : ['http://localhost:3000', 'http://localhost:5000'];
    
    // Check if origin is in allowed list
    if (allowedOrigins.includes(origin) || allowedOrigins.includes('*')) {
      callback(null, true);
    } else if (process.env.NODE_ENV === 'development') {
      // In development, allow all origins
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  maxAge: 86400,
};

app.use(cors(corsOptions));
app.options('*', cors(corsOptions));

// Body parser
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Data Sanitization
app.use(mongoSanitize({ replaceWith: '_' }));
app.use(xss());
app.use(hpp({ whitelist: ['sort', 'fields', 'page', 'limit'] }));

// Compression
app.use(compression());

// ==================== RATE LIMITING ====================

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: {
    success: false,
    message: 'Too many requests from this IP, please try again later.',
    retryAfter: `${Math.floor((Number(process.env.LOCK_TIME) || 600000) / 60000)} minutes`
  },
  standardHeaders: true,
  legacyHeaders: false,
});

app.use('/api/', apiLimiter);
const authLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 5,
  skipSuccessfulRequests: true,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    const now = Date.now();
    const lockTimeMs = Number(process.env.LOCK_TIME) || 10 * 60 * 1000;
    const lockUntil = now + lockTimeMs;

    const remainingSeconds = Math.floor((lockUntil - now) / 1000);
    const remainingMinutes = Math.floor(remainingSeconds / 60);

    console.log(`🔒 Rate limit exceeded for ${req.ip}`);
    console.log(`   - Remaining: ${remainingMinutes}m ${remainingSeconds % 60}s (${remainingSeconds} total seconds)`);

    res.status(423).json({
      success: false,
      code: 'ACCOUNT_LOCKED',
      message: `Too many authentication attempts. Please try again in ${remainingMinutes} minute${remainingMinutes !== 1 ? 's' : ''}.`,
      lockUntil: lockUntil,
      remainingSeconds: remainingSeconds,
      remainingMinutes: remainingMinutes,
    });
  }
});

app.use('/api/auth/login', authLimiter);
app.use('/api/auth/register', authLimiter);
app.use('/api/auth/forgot-password', authLimiter);

const resetLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 3,
  message: {
    success: false,
    message: 'Too many password reset attempts. Please try again in 1 hour.',
    retryAfter: '1 hour'
  },
});

app.use('/api/auth/reset-password', resetLimiter);

//           LOGGING 

if (process.env.NODE_ENV === 'development') {
  app.use((req, res, next) => {
    console.log(`${req.method} ${req.path} - ${req.ip}`);
    next();
  });
}

//           ROUTES 

   // for web
   app.get('/', (req, res) => {
  res.json({
    success: true,
    message: 'Welcome to FitMetrics API',
    version: '1.0.0',
    status: 'Running',
    endpoints: {
      health: '/api/health',
      api: '/api',
      auth: '/api/auth',
      user: '/api/user'
    }
  });
});
app.use('/api/auth', require('./routes/auth'));
app.use('/api/user', require('./routes/user'));

// Health check
app.get('/api/health', (req, res) => {
  res.json({ 
    success: true,
    status: 'OK', 
    message: 'Server is running',
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development',
    uptime: process.uptime(),
  });
});

// API info
app.get('/api', (req, res) => {
  res.json({
    success: true,
    message: 'Workout Tracker API',
    version: '1.0.0',
    endpoints: {
      auth: '/api/auth',
      user: '/api/user',
      health: '/api/health'
    }
  });
});

 //         ERROR HANDLING 

// 404 Handler
app.use((req, res, next) => {
  res.status(404).json({
    success: false,
    message: `Route ${req.originalUrl} not found`,
    code: 'ROUTE_NOT_FOUND'
  });
});

// Global Error Handler
app.use((err, req, res, next) => {
  if (err.name === 'ValidationError') {
    const errors = Object.values(err.errors).map(e => ({
      field: e.path,
      message: e.message
    }));
    
    return res.status(400).json({
      success: false,
      message: 'Validation failed',
      errors
    });
  }

  if (err.code === 11000) {
    const field = Object.keys(err.keyPattern)[0];
    return res.status(400).json({
      success: false,
      message: `${field.charAt(0).toUpperCase() + field.slice(1)} already exists`,
      field
    });
  }

  if (err.name === 'CastError') {
    return res.status(400).json({
      success: false,
      message: 'Invalid ID format',
      code: 'INVALID_ID'
    });
  }

  if (err.name === 'JsonWebTokenError') {
    return res.status(401).json({
      success: false,
      message: 'Invalid token',
      code: 'INVALID_TOKEN'
    });
  }

  if (err.name === 'TokenExpiredError') {
    return res.status(401).json({
      success: false,
      message: 'Token expired',
      code: 'TOKEN_EXPIRED'
    });
  }

  if (err.message === 'Not allowed by CORS') {
    return res.status(403).json({
      success: false,
      message: 'CORS policy violation',
      code: 'CORS_ERROR'
    });
  }

  const statusCode = err.statusCode || 500;
  const message = process.env.NODE_ENV === 'production' 
    ? 'Something went wrong. Please try again later.' 
    : err.message;

  res.status(statusCode).json({
    success: false,
    message,
    code: err.code || 'SERVER_ERROR',
    ...(process.env.NODE_ENV === 'development' && { 
      stack: err.stack,
      error: err 
    })
  });
});

// ==================== GRACEFUL SHUTDOWN ====================

process.on('unhandledRejection', (err) => {
  console.error('❌ UNHANDLED REJECTION! Shutting down...');
  console.error(err.name, err.message);
  server.close(() => {
    process.exit(1);
  });
});

process.on('uncaughtException', (err) => {
  console.error('❌ UNCAUGHT EXCEPTION! Shutting down...');
  console.error(err.name, err.message);
  process.exit(1);
});

process.on('SIGTERM', () => {
  console.log(' SIGTERM received. Shutting down gracefully...');
  server.close(() => {
    console.log(' Process terminated');
  });
});

// ==================== START SERVER ====================

const PORT = process.env.PORT || 5000;
const server = app.listen(PORT, () => {
  console.log('');
  console.log('='.repeat(50));
  console.log(` Server running on port ${PORT}`);
  console.log(`📧 Email configured: ${process.env.EMAIL_USER ? ' YES' : ' NO'}`);
  
});

module.exports = app; 