const nodemailer = require('nodemailer');

const sendEmail = async (options) => {
  // Extract env variables with multi-name support
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

  if (isGmail && user && pass) {
    // Strategy 1: Direct SSL on Port 465 (Preferred for Cloud Data Centers)
    try {
      const transporter465 = nodemailer.createTransport({
        host: 'smtp.gmail.com',
        port: 465,
        secure: true,
        auth: { user, pass },
        tls: { rejectUnauthorized: false },
        connectionTimeout: 10000 // 10 sec timeout
      });
      const info = await transporter465.sendMail(message);
      return info;
    } catch (err465) {
      console.warn('[SMTP Warning] Gmail Port 465 failed, attempting fallback to Service transport:', err465.message);
      // Strategy 2: Fallback to service: 'gmail' (Port 587 STARTTLS)
      const transporterService = nodemailer.createTransport({
        service: 'gmail',
        auth: { user, pass }
      });
      return await transporterService.sendMail(message);
    }
  } else if (host && user && pass) {
    const port = process.env.SMTP_PORT ? parseInt(process.env.SMTP_PORT, 10) : 587;
    const transporter = nodemailer.createTransport({
      host: host,
      port: port,
      secure: port === 465,
      auth: { user, pass },
      tls: { rejectUnauthorized: false }
    });
    return await transporter.sendMail(message);
  } else {
    // Development fallback using Ethereal
    try {
      const testAccount = await nodemailer.createTestAccount();
      const transporter = nodemailer.createTransport({
        host: "smtp.ethereal.email",
        port: 587,
        secure: false,
        auth: { user: testAccount.user, pass: testAccount.pass }
      });
      const info = await transporter.sendMail(message);
      console.log('[SMTP Ethereal Preview]: %s', nodemailer.getTestMessageUrl(info));
      return info;
    } catch (e) {
      console.warn('[SMTP Warning] Ethereal fallback failed. Message to %s: %s', options.email, options.message);
    }
  }
};

module.exports = sendEmail;


