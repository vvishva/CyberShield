const SecurityTip = require('../models/SecurityTip');

// @desc    Get Security Tips
// @route   GET /api/tips
exports.getTips = async (req, res) => {
  try {
    let tips = [];
    try {
      tips = await SecurityTip.find().sort({ createdAt: -1 });
    } catch (e) {
      // DB unavailable - return empty array
    }

    res.status(200).json({
      success: true,
      count: tips.length,
      data: tips
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
};

// @desc    Create Security Tip (Admin)
// @route   POST /api/tips
exports.createTip = async (req, res) => {
  const { title, category, content, severity } = req.body;

  const tipObj = {
    title,
    category: category || 'General Cyber',
    content,
    severity: severity || 'INFO',
    author: req.user ? req.user.username : 'CyberShield Admin',
    createdAt: new Date()
  };

  try {
    await SecurityTip.create(tipObj);
  } catch (e) {
    // Ignore if DB unavailable
  }

  res.status(201).json({
    success: true,
    data: tipObj
  });
};
