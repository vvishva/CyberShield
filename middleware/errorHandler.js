const errorHandler = (err, req, res, next) => {
  console.error('[CyberShield API Error]', err.stack || err.message);

  res.status(err.statusCode || 500).json({
    success: false,
    error: err.message || 'Server Error'
  });
};

module.exports = errorHandler;
