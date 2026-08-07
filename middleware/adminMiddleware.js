const admin = (req, res, next) => {
  if (req.user && req.user.role === 'admin') {
    next();
  } else {
    res.status(403).json({
      success: false,
      error: 'Forbidden. Access restricted to CyberShield Administrators only.'
    });
  }
};

module.exports = { admin };
