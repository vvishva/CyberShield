const PDFDocument = require('pdfkit');

/**
 * Generates a professional CyberShield AI Security Report PDF Buffer
 * @param {Object} data Report metadata and scan findings
 * @returns {Promise<Buffer>} PDF binary buffer
 */
function generatePdfReport(data = {}) {
  return new Promise((resolve, reject) => {
    try {
      const doc = new PDFDocument({ margin: 40, size: 'A4' });
      const buffers = [];

      doc.on('data', b => buffers.push(b));
      doc.on('end', () => resolve(Buffer.concat(buffers)));
      doc.on('error', err => reject(err));

      // Color Palette
      const primaryColor = '#00d4ff'; // Cyan
      const darkBg = '#0b0f1a';      // Dark Navy
      const cardBg = '#131b2e';      // Card BG
      const textWhite = '#ffffff';
      const textMuted = '#9ca3af';
      const greenColor = '#00c896';
      const redColor = '#ef4444';
      const amberColor = '#f59e0b';

      const target = data.target || data.url || 'Target Asset';
      const title = data.title || `Security Audit Report for ${target}`;
      const status = data.overallStatus || data.status || 'Safe';
      const riskScore = data.riskScore != null ? data.riskScore : 0;
      const secScore = data.securityScore != null ? data.securityScore : (100 - riskScore);
      const reportId = data.reportId || `REP-${Date.now().toString(36).toUpperCase()}`;
      const dateStr = data.createdAt ? new Date(data.createdAt).toUTCString() : new Date().toUTCString();
      const analyst = data.user ? (data.user.username || data.user.email || 'Analyst') : 'System Analyst';

      // ── Background Header Banner ──
      doc.rect(0, 0, 595.28, 90).fill(darkBg);
      doc.rect(0, 88, 595.28, 2).fill(primaryColor);

      // Logo / Title Header Text
      doc.fillColor(primaryColor).fontSize(20).font('Helvetica-Bold').text('CYBERSHIELD AI', 40, 25);
      doc.fillColor(textWhite).fontSize(10).font('Helvetica').text('Enterprise Security Operations Center Report', 40, 50);

      // Header Meta Text Right
      doc.fillColor(textMuted).fontSize(9).font('Helvetica')
        .text(`Report ID: ${reportId}`, 360, 25, { align: 'right' })
        .text(`Generated: ${dateStr}`, 360, 38, { align: 'right' })
        .text(`Analyst: ${analyst}`, 360, 51, { align: 'right' });

      doc.y = 110;

      // ── Report Title ──
      doc.fillColor(textWhite).fontSize(15).font('Helvetica-Bold').text(title, 40, 110);
      doc.moveDown(0.8);

      // ── Executive Summary Cards ──
      const summaryY = doc.y;
      
      // Card 1: Target
      doc.rect(40, summaryY, 245, 55).fillAndStroke(cardBg, '#1e293b');
      doc.fillColor(textMuted).fontSize(8).font('Helvetica-Bold').text('TARGET ASSET', 52, summaryY + 10);
      doc.fillColor(textWhite).fontSize(11).font('Helvetica-Bold').text(target.length > 30 ? target.substring(0, 30) + '...' : target, 52, summaryY + 25);

      // Card 2: Security Verdict
      let verdictColor = greenColor;
      if (['High Risk', 'Phishing', 'Critical', 'Malicious'].includes(status)) verdictColor = redColor;
      else if (['Medium Risk'].includes(status)) verdictColor = amberColor;

      doc.rect(300, summaryY, 255, 55).fillAndStroke(cardBg, '#1e293b');
      doc.fillColor(textMuted).fontSize(8).font('Helvetica-Bold').text('SECURITY VERDICT', 312, summaryY + 10);
      doc.fillColor(verdictColor).fontSize(13).font('Helvetica-Bold').text(String(status).toUpperCase(), 312, summaryY + 25);

      // Card 3: Security Score
      const card2Y = summaryY + 65;
      doc.rect(40, card2Y, 245, 55).fillAndStroke(cardBg, '#1e293b');
      doc.fillColor(textMuted).fontSize(8).font('Helvetica-Bold').text('SECURITY SCORE', 52, card2Y + 10);
      doc.fillColor(primaryColor).fontSize(16).font('Helvetica-Bold').text(`${secScore} / 100`, 52, card2Y + 25);

      // Card 4: Risk Score
      doc.rect(300, card2Y, 255, 55).fillAndStroke(cardBg, '#1e293b');
      doc.fillColor(textMuted).fontSize(8).font('Helvetica-Bold').text('RISK EVALUATION', 312, card2Y + 10);
      doc.fillColor(verdictColor).fontSize(16).font('Helvetica-Bold').text(`${riskScore}% Risk`, 312, card2Y + 25);

      doc.y = card2Y + 75;

      // ── Section 1: Technical Findings ──
      doc.fillColor(primaryColor).fontSize(12).font('Helvetica-Bold').text('1. Technical Audit Findings', 40, doc.y);
      doc.moveDown(0.4);

      const details = data.details || {};
      const networkData = [
        ['HTTPS Encryption', details.hasHttps ? 'ENABLED (Secure TLS Channel)' : 'DISABLED / Plaintext Traffic'],
        ['Resolved IP', details.resolvedIp || 'N/A'],
        ['Protocol', details.protocol || 'https:'],
        ['Server Banner', details.headerChecks?.serverBanner ? 'DISCLOSED (Server banner exposed)' : 'HIDDEN (Protected)']
      ];

      // Table Drawing
      let tableY = doc.y;
      networkData.forEach(([label, val], idx) => {
        const rowY = tableY + idx * 22;
        doc.rect(40, rowY, 180, 22).fillAndStroke('#0f172a', '#1e293b');
        doc.rect(220, rowY, 335, 22).fillAndStroke('#0b0f1a', '#1e293b');
        doc.fillColor(textMuted).fontSize(9).font('Helvetica-Bold').text(label, 48, rowY + 6);
        doc.fillColor(textWhite).fontSize(9).font('Helvetica').text(String(val), 228, rowY + 6);
      });

      doc.y = tableY + networkData.length * 22 + 18;

      // ── Section 2: Security Header Audit ──
      doc.fillColor(primaryColor).fontSize(12).font('Helvetica-Bold').text('2. Security Header Audit', 40, doc.y);
      doc.moveDown(0.4);

      const headers = details.headerChecks || {};
      const headerData = [
        ['Strict-Transport-Security (HSTS)', headers.hsts ? 'PRESENT' : 'MISSING'],
        ['Content-Security-Policy (CSP)', headers.csp ? 'PRESENT' : 'MISSING'],
        ['X-Frame-Options (Clickjacking)', headers.xFrameOptions ? 'PRESENT' : 'MISSING'],
        ['X-Content-Type-Options', headers.xContentTypeOptions ? 'PRESENT' : 'MISSING'],
        ['Referrer-Policy', headers.referrerPolicy ? 'PRESENT' : 'MISSING']
      ];

      let hTableY = doc.y;
      headerData.forEach(([hLabel, hVal], idx) => {
        const rowY = hTableY + idx * 22;
        const isPresent = hVal === 'PRESENT';
        doc.rect(40, rowY, 220, 22).fillAndStroke('#0f172a', '#1e293b');
        doc.rect(260, rowY, 295, 22).fillAndStroke('#0b0f1a', '#1e293b');
        doc.fillColor(textMuted).fontSize(9).font('Helvetica-Bold').text(hLabel, 48, rowY + 6);
        doc.fillColor(isPresent ? greenColor : redColor).fontSize(9).font('Helvetica-Bold').text(hVal, 268, rowY + 6);
      });

      doc.y = hTableY + headerData.length * 22 + 18;

      // ── Section 3: Recommendations ──
      doc.fillColor(primaryColor).fontSize(12).font('Helvetica-Bold').text('3. AI Remediation Recommendations', 40, doc.y);
      doc.moveDown(0.4);

      const recs = data.recommendations || details.recommendations || [
        'Enforce HTTPS across all application endpoints with HSTS enabled.',
        'Configure Content-Security-Policy to restrict unauthorized script execution.',
        'Enable X-Frame-Options header to protect against Clickjacking attacks.',
        'Regularly monitor domain reputation and SSL certificate validity.'
      ];

      recs.forEach(r => {
        if (doc.y > 750) doc.addPage();
        doc.fillColor(primaryColor).fontSize(9).text('• ', 48, doc.y);
        doc.fillColor(textWhite).fontSize(9).font('Helvetica').text(String(r), 60, doc.y - 9, { width: 495 });
        doc.moveDown(0.3);
      });

      // ── Footer ──
      doc.rect(40, 780, 515, 1).fill('#1e293b');
      doc.fillColor(textMuted).fontSize(8).font('Helvetica')
        .text('CyberShield AI Operations Center — Confidential Security Audit Report', 40, 790, { align: 'center' });

      doc.end();
    } catch (err) {
      reject(err);
    }
  });
}

module.exports = { generatePdfReport };
