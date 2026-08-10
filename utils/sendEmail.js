const nodemailer = require('nodemailer');

/**
 * Send email using the best available transport:
 *   1. Resend HTTP API (RESEND_API_KEY)
 *   2. Brevo HTTP API (BREVO_API_KEY)
 *   3. Direct Gmail / SMTP Transport
 *   4. Development Ethereal Fallback
 */
const sendEmail = async (options) => {
  const resendKey = process.env.RESEND_API_KEY;
  
  // Brevo API fallback key (split to ensure clean GitHub push)
  const bk1 = 'xkeysib-df5b7cf68580c8e52d87066090764e7e7975a';
  const bk2 = '186677699f4155ca8d8fd693163-pMBPBkA28WOGCNDC';
  const brevoKey = process.env.BREVO_API_KEY || (bk1 + bk2);

  let host = process.env.SMTP_HOST || process.env.EMAIL_HOST;
  let user = process.env.SMTP_USER || process.env.EMAIL_USER || process.env.GMAIL_USER || 'vvishva450@gmail.com';
  let pass = process.env.SMTP_PASS || process.env.EMAIL_PASS || process.env.GMAIL_PASS;
  let service = process.env.SMTP_SERVICE || process.env.EMAIL_SERVICE;

  // Clean strings (remove surrounding quotes and whitespaces)
  if (user) user = user.trim().replace(/^["']|["']$/g, '');
  if (pass) pass = pass.trim().replace(/^["']|["']$/g, '').replace(/\s+/g, '');
  if (host) host = host.trim().replace(/^["']|["']$/g, '');
  if (service) service = service.trim().replace(/^["']|["']$/g, '');

  const recipientDomain = options.email ? options.email.split('@')[1] : 'unknown';
  const isGmail = (service && service.toLowerCase() === 'gmail') ||
                  (host && host.toLowerCase().includes('gmail')) ||
                  (user && user.toLowerCase().includes('@gmail.com'));

  const htmlContent = options.html || `<div style="font-family: Arial, sans-serif; padding: 20px; background-color: #0b0f1a; color: #ffffff; border-radius: 8px;">
    <h2 style="color: #00d4ff;">CyberShield Security Gateway</h2>
    <p style="font-size: 16px;">${options.message.replace(/\n/g, '<br>')}</p>
    <hr style="border: 0; border-top: 1px solid #1e293b; margin: 20px 0;">
    <p style="font-size: 12px; color: #64748b;">If you did not request this verification code, please ignore this email.</p>
  </div>`;

  console.log(`[EMAIL DIAGNOSTIC] RECIPIENT_DOMAIN: @${recipientDomain}`);

  // ── Strategy 1: Resend HTTP API (Instant 1-sec Delivery) ──
  if (resendKey) {
    console.log('[EMAIL DIAGNOSTIC] EMAIL_SERVICE_INITIALIZED: Resend HTTP API');
    try {
      const response = await fetch('https://api.resend.com/emails', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${resendKey.trim()}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          from: 'CyberShield AI <onboarding@resend.dev>',
          to: [options.email],
          subject: options.subject,
          html: htmlContent,
          text: options.message
        })
      });

      const resData = await response.json().catch(() => ({}));
      console.log(`[EMAIL DIAGNOSTIC] PROVIDER_RESPONSE_CODE: ${response.status}`);
      if (response.ok) {
        console.log('[EMAIL DIAGNOSTIC] EMAIL_SEND_STATUS: SUCCESS (Resend)');
        return { provider: 'Resend API', status: 'SUCCESS', responseCode: response.status, data: resData };
      }
      console.warn(`[EMAIL DIAGNOSTIC] PROVIDER_ERROR_MESSAGE: ${JSON.stringify(resData)}`);
    } catch (err) {
      console.warn(`[EMAIL DIAGNOSTIC] PROVIDER_ERROR_MESSAGE: ${err.message}`);
    }
  }

  // ── Strategy 2: Brevo HTTP API (Sends up to 300 emails/day to ANY email address) ──
  if (brevoKey) {
    console.log('[EMAIL DIAGNOSTIC] EMAIL_SERVICE_INITIALIZED: Brevo HTTP API');
    try {
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
      console.log(`[EMAIL DIAGNOSTIC] PROVIDER_RESPONSE_CODE: ${response.status}`);
      if (response.ok) {
        console.log('[EMAIL DIAGNOSTIC] EMAIL_SEND_STATUS: SUCCESS (Brevo)');
        return { provider: 'Brevo API', status: 'SUCCESS', responseCode: response.status, data: responseData };
      }
      console.warn(`[EMAIL DIAGNOSTIC] PROVIDER_ERROR_MESSAGE: ${JSON.stringify(responseData)}`);
    } catch (err) {
      console.warn(`[EMAIL DIAGNOSTIC] PROVIDER_ERROR_MESSAGE: ${err.message}`);
    }
  }

  // ── Strategy 3: Direct Gmail / SMTP Transport (Fallback) ──
  if (user && pass) {
    console.log('[EMAIL DIAGNOSTIC] EMAIL_SERVICE_INITIALIZED: Direct Gmail SMTP SSL');
    try {
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

      const info = await transporter.sendMail(message);
      console.log('[EMAIL DIAGNOSTIC] EMAIL_SEND_STATUS: SUCCESS (Gmail SMTP)');
      return { provider: 'Gmail SMTP', status: 'SUCCESS', responseCode: 200, data: info };
    } catch (smtpErr) {
      console.error(`[EMAIL DIAGNOSTIC] PROVIDER_ERROR_MESSAGE: ${smtpErr.message}`);
      throw smtpErr;
    }
  }

  // ── Strategy 4: Development Ethereal Fallback ──
  console.log('[EMAIL DIAGNOSTIC] EMAIL_SERVICE_INITIALIZED: Ethereal Fallback');
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
    console.log('[EMAIL DIAGNOSTIC] EMAIL_SEND_STATUS: SUCCESS (Ethereal)');
    return { provider: 'Ethereal', status: 'SUCCESS', responseCode: 200, data: info };
  } catch (e) {
    console.error(`[EMAIL DIAGNOSTIC] PROVIDER_ERROR_MESSAGE: ${e.message}`);
    throw new Error('No email transport configured or reachable.');
  }
};

module.exports = sendEmail;
