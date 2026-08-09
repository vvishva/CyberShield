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
    const secret = process.env.JWT_SECRET || 'cybershield_super_secret_jwt_key_2026_cse_final_year';
    const decoded = jwt.verify(token, secret);

    try {
      req.user = await User.findById(decoded.id).select('-password');
    } catch (e) {
      // Fallback user object if database is disconnected
      req.user = {
        _id: decoded.id,
        username: decoded.username || 'Demo User',
        email: decoded.email || 'user@cybershield.io',
        role: decoded.role || 'user'
      };
    }

    if (!req.user) {
      req.user = {
        _id: decoded.id,
        username: decoded.username || 'User',
        email: 'user@cybershield.io',
        role: decoded.role || 'user'
      };
    }

    next();
  } catch (err) {
    return res.status(401).json({
      success: false,
      error: 'Not authorized. Invalid or expired token.'
    });
  }
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

module.exports = { protect, authorize };
