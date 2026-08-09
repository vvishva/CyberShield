const Report = require('../models/Report');
const Scan = require('../models/Scan');

// @desc    Get All Reports
// @route   GET /api/reports
exports.getReports = async (req, res) => {
  try {
    let reports = [];
    try {
      const query = req.user ? { user: req.user._id } : {};
      reports = await Report.find(query).sort({ createdAt: -1 });
    } catch (e) {
      // DB unavailable - return empty array
    }

    res.status(200).json({
      success: true,
      count: reports.length,
      data: reports
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
};

// @desc    Generate New Security Report
// @route   POST /api/reports/generate
exports.generateReport = async (req, res) => {
  const { title, target, scanType, riskScore, findings, recommendations } = req.body;

  const reportId = `REP-${new Date().getFullYear()}-${Math.floor(1000 + Math.random() * 9000)}`;

  let overallStatus = 'Safe';
  if (riskScore >= 70) overallStatus = 'High Risk';
  else if (riskScore >= 35) overallStatus = 'Medium Risk';

  const reportObj = {
    reportId,
    user: req.user ? req.user._id : null,
    title: title || `Audit Report for ${target}`,
    scanType: scanType || 'url_phishing',
    target: target || 'https://example.com',
    overallStatus,
    riskScore: riskScore || 0,
    findings: findings || [],
    recommendations: recommendations || ['Regular monitoring recommended.'],
    createdAt: new Date()
  };

  try {
    await Report.create(reportObj);
  } catch (e) {
    // Ignore if DB unavailable
  }

  res.status(201).json({
    success: true,
    data: reportObj
  });
};

// @desc    Export Reports or Scans to CSV format
// @route   GET /api/reports/export-csv
exports.exportCsv = async (req, res) => {
  try {
    const query = req.user ? { user: req.user._id } : {};
    const reports = await Report.find(query).sort({ createdAt: -1 }).lean();
    
    let csvContent = 'ID,Target,Scan Type,Status,Risk Score,Date\n';
    if (reports.length > 0) {
      reports.forEach(r => {
        csvContent += `${r.reportId},${r.target},${r.scanType},${r.overallStatus},${r.riskScore}%,${r.createdAt}\n`;
      });
    } else {
      csvContent += 'No reports available,,,\n';
    }

    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename="CyberShield_Security_Report.csv"');
    res.status(200).send(csvContent);
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
};
