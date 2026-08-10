const nodemailer = require('nodemailer');

/**
 * Send email using the best available transport:
 *   1. Brevo HTTP API (BREVO_API_KEY) - Works on ALL cloud platforms (Render, AWS, etc.)
 *   2. Gmail SMTP (SMTP_USER + SMTP_PASS) - Works locally, blocked by some cloud platforms
 *   3. Ethereal test account - Development fallback
 */
const sendEmail = async (options) => {
  const brevoKey = process.env.BREVO_API_KEY;

  // ── Strategy 1: Direct Gmail SMTP over Port 465 SSL (Passes DMARC & Arrives in Inbox) ──
  if (user && pass) {
    let transporter;
    if (isGmail || !host) {
      transporter = nodemailer.createTransport({
        host: 'smtp.gmail.com',
        port: 465,
        secure: true, // SSL
        auth: { user, pass },
        tls: { rejectUnauthorized: false }
      });
    } else {
      const port = process.env.SMTP_PORT ? parseInt(process.env.SMTP_PORT, 10) : 587;
      transporter = nodemailer.createTransport({
        host, port,
        secure: port === 465,
        auth: { user, pass },
        tls: { rejectUnauthorized: false }
      });
    }

    const message = {
      from: `${process.env.FROM_NAME || 'CyberShield AI Security'} <${user}>`,
      to: options.email,
      subject: options.subject,
      text: options.message,
      html: options.html || `<div style="font-family: Arial, sans-serif; padding: 20px; background-color: #0b0f1a; color: #ffffff; border-radius: 8px;">
        <h2 style="color: #00d4ff;">CyberShield Security Gateway</h2>
        <p style="font-size: 16px;">${options.message.replace(/\n/g, '<br>')}</p>
        <hr style="border: 0; border-top: 1px solid #1e293b; margin: 20px 0;">
        <p style="font-size: 12px; color: #64748b;">If you did not request this verification code, please ignore this email.</p>
      </div>`
    };

    return await transporter.sendMail(message);
  }

  // ── Strategy 2: Brevo HTTP API ──
  if (brevoKey) {
    const senderEmail = process.env.FROM_EMAIL || user || 'noreply@cybershield.io';
    const senderName = process.env.FROM_NAME || 'CyberShield AI Security';

    const htmlContent = options.html || `<div style="font-family: Arial, sans-serif; padding: 20px; background-color: #0b0f1a; color: #ffffff; border-radius: 8px;">
      <h2 style="color: #00d4ff;">CyberShield Security Gateway</h2>
      <p style="font-size: 16px;">${options.message.replace(/\n/g, '<br>')}</p>
      <hr style="border: 0; border-top: 1px solid #1e293b; margin: 20px 0;">
      <p style="font-size: 12px; color: #64748b;">If you did not request this, please ignore this email.</p>
    </div>`;

    const body = JSON.stringify({
      sender: { name: senderName, email: senderEmail },
      to: [{ email: options.email }],
      subject: options.subject,
      htmlContent: htmlContent,
      textContent: options.message
    });

    const response = await fetch('https://api.brevo.com/v3/smtp/email', {
      method: 'POST',
      headers: {
        'accept': 'application/json',
        'api-key': brevoKey.trim(),
        'content-type': 'application/json'
      },
      body: body
    });

    const responseData = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(`Email delivery failed: ${responseData.message || response.statusText}`);
    }
    return responseData;
  }

  // ── Strategy 3: Ethereal (Development Only) ──
  try {
    const testAccount = await nodemailer.createTestAccount();
    const transporter = nodemailer.createTransport({
      host: 'smtp.ethereal.email', port: 587, secure: false,
      auth: { user: testAccount.user, pass: testAccount.pass }
    });
    const message = {
      from: 'CyberShield AI <noreply@cybershield.io>',
      to: options.email,
      subject: options.subject,
      text: options.message
    };
    const info = await transporter.sendMail(message);
    console.log('[Dev Email Preview]: %s', nodemailer.getTestMessageUrl(info));
    return info;
  } catch (e) {
    console.warn('[Email Warning] No email transport available.');
    throw new Error('No email transport configured.');
  }
};

module.exports = sendEmail;
