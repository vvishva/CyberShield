const nodemailer = require('nodemailer');

/**
 * Send email using the best available transport:
 *   1. Brevo HTTP API (BREVO_API_KEY) - Works on ALL cloud platforms (Render, AWS, etc.)
 *   2. Gmail SMTP (SMTP_USER + SMTP_PASS) - Works locally, blocked by some cloud platforms
 *   3. Ethereal test account - Development fallback
 */
const sendEmail = async (options) => {
  // Extract env variables with multi-name support
  const brevoKey = process.env.BREVO_API_KEY;
  let host = process.env.SMTP_HOST || process.env.EMAIL_HOST;
  let user = process.env.SMTP_USER || process.env.EMAIL_USER || process.env.GMAIL_USER;
  let pass = process.env.SMTP_PASS || process.env.EMAIL_PASS || process.env.GMAIL_PASS;
  let service = process.env.SMTP_SERVICE || process.env.EMAIL_SERVICE;

  // Clean strings (remove surrounding quotes and whitespaces)
  if (user) user = user.trim().replace(/^["']|["']$/g, '');
  if (pass) pass = pass.trim().replace(/^["']|["']$/g, '').replace(/\s+/g, '');
  if (host) host = host.trim().replace(/^["']|["']$/g, '');
  if (service) service = service.trim().replace(/^["']|["']$/g, '');

  const isGmail = (service && service.toLowerCase() === 'gmail') ||
                  (host && host.toLowerCase().includes('gmail')) ||
                  (user && user.toLowerCase().includes('@gmail.com'));

  const htmlContent = options.html || `<div style="font-family: Arial, sans-serif; padding: 20px; background-color: #0b0f1a; color: #ffffff; border-radius: 8px;">
    <h2 style="color: #00d4ff;">CyberShield Security Gateway</h2>
    <p style="font-size: 16px;">${options.message.replace(/\n/g, '<br>')}</p>
    <hr style="border: 0; border-top: 1px solid #1e293b; margin: 20px 0;">
    <p style="font-size: 12px; color: #64748b;">If you did not request this verification code, please ignore this email.</p>
  </div>`;

  // ── Strategy 1: Brevo HTTP API (Best for Cloud Deployments like Render/AWS) ──
  if (brevoKey) {
    const senderEmail = process.env.FROM_EMAIL || user || 'vvishva450@gmail.com';
    const senderName = process.env.FROM_NAME || 'CyberShield AI Security';

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
      console.error('[Brevo API Error]', response.status, responseData);
      throw new Error(`Email delivery failed: ${responseData.message || response.statusText}`);
    }
    return responseData;
  }

  // ── Strategy 2: Direct Gmail / SMTP Transport (Fallback) ──
  if (user && pass) {
    let transporter;
    if (isGmail || !host) {
      transporter = nodemailer.createTransport({
        host: 'smtp.gmail.com',
        port: 465,
        secure: true,
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
      html: htmlContent
    };

    return await transporter.sendMail(message);
  }

  // ── Strategy 3: Development Ethereal Fallback ──
  try {
    const testAccount = await nodemailer.createTestAccount();
    const transporter = nodemailer.createTransport({
      host: 'smtp.ethereal.email', port: 587, secure: false,
      auth: { user: testAccount.user, pass: testAccount.pass }
    });
    const info = await transporter.sendMail({
      from: 'CyberShield AI <noreply@cybershield.io>',
      to: options.email,
      subject: options.subject,
      text: options.message,
      html: htmlContent
    });
    console.log('[Dev Email Preview]: %s', nodemailer.getTestMessageUrl(info));
    return info;
  } catch (e) {
    console.warn('[Email Warning] No email transport available.');
    throw new Error('No email transport configured.');
  }
};

module.exports = sendEmail;
