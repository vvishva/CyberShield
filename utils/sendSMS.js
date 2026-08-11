/**
 * CyberShield — SMS Sender Utility
 *
 * Uses Twilio REST API via native fetch (no SDK dependency).
 * Credentials are read exclusively from environment variables.
 * The OTP value is NEVER logged or returned to the caller.
 *
 * Required env vars (set in Render dashboard):
 *   TWILIO_ACCOUNT_SID   — e.g. ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
 *   TWILIO_AUTH_TOKEN    — e.g. xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
 *   TWILIO_PHONE_NUMBER  — e.g. +15005550006
 */

/**
 * Send an SMS via Twilio.
 *
 * @param {string} to      - Recipient phone in E.164 format (e.g. +919876543210)
 * @param {string} message - SMS body text (keep under 160 chars for a single segment)
 * @returns {Promise<{ provider: string, status: string, sid: string }>}
 * @throws  Error('SMS_NOT_CONFIGURED') if env vars are missing
 * @throws  Error with user-facing message on delivery failure
 */
const sendSMS = async (to, message) => {
  const sid   = process.env.TWILIO_ACCOUNT_SID;
  const token = process.env.TWILIO_AUTH_TOKEN;
  const from  = process.env.TWILIO_PHONE_NUMBER;

  // Validate configuration — fail fast and clearly
  if (!sid || !token || !from) {
    console.error('[SMS DIAGNOSTIC] SMS_NOT_CONFIGURED: One or more Twilio env vars are missing.');
    throw new Error('SMS_NOT_CONFIGURED');
  }

  const url = `https://api.twilio.com/2010-04-01/Accounts/${sid}/Messages.json`;

  const body = new URLSearchParams();
  body.append('To',   to);
  body.append('From', from);
  body.append('Body', message);

  console.log(`[SMS DIAGNOSTIC] Sending SMS to: ${to.replace(/\d(?=\d{4})/g, '*')}`);

  let response;
  try {
    response = await fetch(url, {
      method:  'POST',
      headers: {
        'Authorization': 'Basic ' + Buffer.from(`${sid}:${token}`).toString('base64'),
        'Content-Type':  'application/x-www-form-urlencoded'
      },
      body: body.toString()
    });
  } catch (networkErr) {
    console.error('[SMS DIAGNOSTIC] NETWORK_ERROR:', networkErr.message);
    throw new Error('SMS delivery failed. Please check your network and try again.');
  }

  let resData = {};
  try {
    resData = await response.json();
  } catch (_) {}

  if (!response.ok) {
    const twilioMsg = resData.message || resData.error_message || 'Unknown Twilio error';
    // Only log technical details — never expose to users
    console.error(`[SMS DIAGNOSTIC] TWILIO_ERROR ${response.status}: ${twilioMsg}`);

    // Map Twilio error codes to user-friendly messages
    if (response.status === 401) {
      throw new Error('SMS service authentication failed. Please contact administrator.');
    }
    if (response.status === 400) {
      // Could be invalid destination number
      throw new Error('Unable to deliver SMS. Please check the phone number and try again.');
    }
    throw new Error('Unable to send verification SMS. Please try again later.');
  }

  console.log(`[SMS DIAGNOSTIC] SMS_SEND_STATUS: SUCCESS SID=${resData.sid}`);
  return {
    provider: 'Twilio',
    status:   resData.status || 'queued',
    sid:      resData.sid || 'unknown'
  };
};

module.exports = sendSMS;
