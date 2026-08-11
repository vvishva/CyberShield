const express = require('express');
const path = require('path');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const swaggerUi = require('swagger-ui-express');
const swaggerSpec = require('../config/swagger');
require('dotenv').config();

const connectDB = require('../config/db');
const errorHandler = require('../middleware/errorHandler');

// Initialize Express App
const app = express();

// Connect to MongoDB
connectDB().then(() => {
  try { require('../utils/seeder').seedAdmin(); } catch(e) {}
});

// Security Middlewares
const isProduction = process.env.NODE_ENV === 'production';

// Safe origin parsing for Python AI service
let pythonOrigin = 'http://localhost:5001';
try {
  if (process.env.PYTHON_AI_URL) {
    pythonOrigin = new URL(process.env.PYTHON_AI_URL).origin;
  }
} catch (_) {}

app.use(helmet({
  contentSecurityPolicy: isProduction ? {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", 'https://cdn.jsdelivr.net', 'https://cdnjs.cloudflare.com', 'https://unpkg.com'],
      styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com', 'https://cdnjs.cloudflare.com'],
      fontSrc: ["'self'", 'https://fonts.gstatic.com', 'https://cdnjs.cloudflare.com'],
      imgSrc: ["'self'", 'data:', 'https:'],
      connectSrc: ["'self'", 'https:', pythonOrigin],
      frameAncestors: ["'none'"],
      baseUri: ["'self'"],
      formAction: ["'self'"]
    }
  } : false // Disable CSP in development for easier debugging
}));
app.use(cors({
  origin: process.env.CORS_ORIGIN || '*',
  credentials: true
}));

// Trust proxy for rate limiting behind render/heroku
app.set('trust proxy', 1);

// Rate Limiter to prevent DoS attacks
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: isProduction ? 100 : 300, // Stricter in production
  message: { success: false, error: 'Too many requests from this IP, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false
});
app.use('/api', limiter);

// Stricter rate limits for auth endpoints
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 20, // Increased to 20 to prevent locking out legitimate users
  message: { success: false, error: 'Too many login attempts, please try again later.' }
});
app.use('/api/auth/login', authLimiter);
app.use('/api/auth/register', authLimiter);

// Body Parser Middleware with size limits
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));

// Disable caching so users always get fresh CSS/JS updates
app.use((req, res, next) => {
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.set('Pragma', 'no-cache');
  res.set('Expires', '0');
  next();
});

// Swagger API Documentation
app.use('/api/docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec, {
  customCss: '.swagger-ui .topbar { display: none }',
  customSiteTitle: 'CyberShield AI Security API Docs'
}));

// Serve Static Assets (Frontend)
const rootDir = path.join(__dirname, '..');
app.use(express.static(path.join(rootDir, 'client')));
app.use('/css', express.static(path.join(rootDir, 'css')));
app.use('/js', express.static(path.join(rootDir, 'js')));
app.use('/images', express.static(path.join(rootDir, 'images')));

// API Routes Registration
app.use('/api/auth', require('../routes/auth'));
app.use('/api/scan', require('../routes/scan'));
app.use('/api/reports', require('../routes/report'));
app.use('/api/user', require('../routes/user'));
app.use('/api/admin', require('../routes/admin'));
app.use('/api/tips', require('../routes/tip'));
app.use('/api/copilot', require('../routes/copilot'));
app.use('/api/events', require('../routes/events').router);
app.use('/api/monitor', require('../routes/monitor'));

// Health Check Endpoint
app.get('/api/health', (req, res) => {
  res.status(200).json({
    status: 'ONLINE',
    system: 'CyberShield AI Web Security Engine',
    timestamp: new Date()
  });
});

// Fallback route serving landing page
app.get('*', (req, res) => {
  res.sendFile(path.join(rootDir, 'client', 'index.html'));
});

// Global Error Handler
app.use(errorHandler);

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log('=======================================================');
  console.log(`   CYBERSHIELD AI SECURITY SYSTEM ACTIVE ON PORT ${PORT} `);
  console.log(`   Access Web Dashboard: http://localhost:${PORT}        `);
  console.log(`   API Documentation: http://localhost:${PORT}/api/docs  `);
  console.log('=======================================================');
});
