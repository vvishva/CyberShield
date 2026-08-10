const nodemailer = require('nodemailer');

const sendEmail = async (options) => {
  let transporter;

  // Extract env variables with multi-name support
  const host = process.env.SMTP_HOST || process.env.EMAIL_HOST;
  const user = process.env.SMTP_USER || process.env.EMAIL_USER || process.env.GMAIL_USER;
  let pass = process.env.SMTP_PASS || process.env.EMAIL_PASS || process.env.GMAIL_PASS;
  const service = process.env.SMTP_SERVICE || process.env.EMAIL_SERVICE;

  // Clean app password if user copy-pasted with spaces
  if (pass) {
    pass = pass.replace(/\s+/g, '');
  }

  const isGmail = (service && service.toLowerCase() === 'gmail') ||
                  (host && host.toLowerCase().includes('gmail')) ||
                  (user && user.toLowerCase().includes('@gmail.com'));

  if (isGmail && user && pass) {
    // Direct SSL on port 465 is the most reliable transport for Gmail on cloud hosts (Render/AWS)
    transporter = nodemailer.createTransport({
      host: 'smtp.gmail.com',
      port: 465,
      secure: true,
      auth: {
        user: user,
        pass: pass
      },
      tls: {
        rejectUnauthorized: false
      }
    });
  } else if (host && user && pass) {
    const port = process.env.SMTP_PORT ? parseInt(process.env.SMTP_PORT, 10) : 587;
    transporter = nodemailer.createTransport({
      host: host,
      port: port,
      secure: port === 465,
      auth: {
        user: user,
        pass: pass
      },
      tls: {
        rejectUnauthorized: false
      }
    });
  } else {
    // Development fallback using Ethereal or Console
    try {
      const testAccount = await nodemailer.createTestAccount();
      transporter = nodemailer.createTransport({
        host: "smtp.ethereal.email",
        port: 587,
        secure: false,
        auth: {
          user: testAccount.user,
          pass: testAccount.pass,
        },
      });
    } catch (e) {
      console.warn('[SMTP Warning] Ethereal fallback unavailable. Message to %s: %s', options.email, options.message);
      return;
    }
  }

  const message = {
    from: `${process.env.FROM_NAME || 'CyberShield AI Security'} <${process.env.FROM_EMAIL || user || 'noreply@cybershield.io'}>`,
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

  const info = await transporter.sendMail(message);
  
  if (!isGmail && !host) {
    console.log('[SMTP Ethereal Preview]: %s', nodemailer.getTestMessageUrl(info));
  }
};

module.exports = sendEmail;

