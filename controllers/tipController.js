const SecurityTip = require('../models/SecurityTip');

// @desc    Get Security Tips
// @route   GET /api/tips
exports.getTips = async (req, res) => {
  try {
    let tips = [];
    try {
      tips = await SecurityTip.find().sort({ createdAt: -1 });
    } catch (e) {}

    if (!tips || tips.length === 0) {
      tips = [
        {
          _id: 'tip_1',
          title: 'Beware of Spear Phishing Emails',
          category: 'Phishing Awareness',
          content: 'Attacker emails often use domain lookalikes (e.g., paypa1.com instead of paypal.com) and urgent language demanding immediate account verification.',
          severity: 'CRITICAL',
          author: 'CyberShield Intelligence'
        },
        {
          _id: 'tip_2',
          title: 'Use Passphrases Over Passwords',
          category: 'Password Safety',
          content: 'Combine 4 random words (e.g., Purple#Tiger$Run&Fast) to create high entropy passwords that are memory friendly and virtually uncrackable.',
          severity: 'IMPORTANT',
          author: 'Security Best Practices'
        },
        {
          _id: 'tip_3',
          title: 'Verify HTTP Headers & SSL Certificates',
          category: 'Safe Browsing',
          content: 'Ensure websites enforce Strict-Transport-Security (HSTS) and valid TLS 1.3 certificates before submitting personal login credentials.',
          severity: 'INFO',
          author: 'Web Standards Team'
        }
      ];
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
  } catch (e) {}

  res.status(201).json({
    success: true,
    data: tipObj
  });
};
