const express = require('express');
const path = require('path');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

const connectDB = require('../config/db');
const errorHandler = require('../middleware/errorHandler');

// Initialize Express App
const app = express();

// Connect to MongoDB
connectDB();

// Security Middlewares
app.use(helmet({
  contentSecurityPolicy: false // Disabled for inline scripts/CDN loading in demo mode
}));
app.use(cors());

// Rate Limiter to prevent DoS attacks
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 300, // Limit each IP to 300 requests per window
  message: { success: false, error: 'Too many requests from this IP, please try again later.' }
});
app.use('/api', limiter);

// Body Parser Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

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
  console.log(`=======================================================`);
  console.log(`   CYBERSHIELD AI SECURITY SYSTEM ACTIVE ON PORT ${PORT} `);
  console.log(`   Access Web Dashboard: http://localhost:${PORT}        `);
  console.log(`=======================================================`);
});
