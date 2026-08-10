const jwt = require('jsonwebtoken');
const User = require('../models/User');

const protect = async (req, res, next) => {
  let token;

  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
    token = req.headers.authorization.split(' ')[1];
  } else if (req.cookies && req.cookies.token) {
    token = req.cookies.token;
  }

  if (!token) {
    return res.status(401).json({
      success: false,
      error: 'Not authorized to access this route. Token missing.'
    });
  }

  try {
    const secret = process.env.JWT_SECRET;
    if (!secret) {
      throw new Error('JWT_SECRET environment variable is required');
    }
    const decoded = jwt.verify(token, secret);

    try {
      req.user = await User.findById(decoded.id).select('-password');
    } catch (e) {
      return res.status(503).json({ success: false, error: 'Database unavailable' });
    }

    if (!req.user) {
      return res.status(401).json({ success: false, error: 'User no longer exists.' });
    }

    // Check if user changed password after the token was issued
    if (req.user.passwordChangedAt) {
      const changedTimestamp = parseInt(req.user.passwordChangedAt.getTime() / 1000, 10);
      if (decoded.iat < changedTimestamp) {
        return res.status(401).json({ success: false, error: 'Password recently changed. Please log in again.' });
      }
    }

    next();
  } catch (err) {
    return res.status(401).json({
      success: false,
      error: 'Not authorized. Invalid or expired token.'
    });
  }
};

// Attach user if a valid token is present, otherwise continue as anonymous.
const optionalAuth = async (req, res, next) => {
  let token;
  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
    token = req.headers.authorization.split(' ')[1];
  } else if (req.cookies && req.cookies.token) {
    token = req.cookies.token;
  }

  if (!token) return next();

  try {
    const secret = process.env.JWT_SECRET;
    if (!secret) return next();
    const decoded = jwt.verify(token, secret);
    try {
      req.user = await User.findById(decoded.id).select('-password');
      if (req.user && req.user.passwordChangedAt) {
        const changedTimestamp = parseInt(req.user.passwordChangedAt.getTime() / 1000, 10);
        if (decoded.iat < changedTimestamp) req.user = null; // invalid token
      }
    } catch (err) {
      req.user = null;
    }
  } catch (err) {
    // Invalid token — treat as anonymous
  }
  next();
};

// Grant access to specific roles
const authorize = (...roles) => {
  return (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role)) {
      return res.status(403).json({
        success: false,
        error: `User role ${req.user ? req.user.role : 'unknown'} is not authorized to access this route.`
      });
    }
    next();
  };
};

module.exports = { protect, optionalAuth, authorize };
