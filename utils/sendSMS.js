/**
 * CyberShield — SMS Sender Utility
 *
 * Supports TextBee SMS Gateway (Android App Gateway) as primary provider,
 * with optional Twilio fallback.
 * Credentials are read exclusively from environment variables.
 * The OTP value is NEVER logged or returned to the caller.
 *
 * TextBee Env Vars (set in Render dashboard):
 *   TEXTBEE_API_KEY      — API key generated from https://textbee.dev dashboard
 *   TEXTBEE_DEVICE_ID    — Unique device ID registered in TextBee app
 *   TEXTBEE_API_BASE_URL — (Optional) Base API URL, defaults to https://api.textbee.dev/api/v1
 *
 * Twilio Env Vars (Fallback if TextBee not set):
 *   TWILIO_ACCOUNT_SID   — ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
 *   TWILIO_AUTH_TOKEN    — xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
 *   TWILIO_PHONE_NUMBER  — +15005550006
 */

/**
 * Send an SMS via TextBee (or Twilio fallback).
 *
 * @param {string} to      - Recipient phone in E.164 format (e.g. +919876543210)
 * @param {string} message - SMS body text
 * @returns {Promise<{ provider: string, status: string, sid?: string }>}
 * @throws  Error('SMS_NOT_CONFIGURED') if env vars are missing
 * @throws  Error with user-facing message on delivery failure
 */
const sendSMS = async (to, message) => {
  const textbeeApiKey  = process.env.TEXTBEE_API_KEY;
  const textbeeDeviceId = process.env.TEXTBEE_DEVICE_ID;
  const textbeeBaseUrl  = process.env.TEXTBEE_API_BASE_URL || 'https://api.textbee.dev/api/v1';

  // ── Strategy 1: TextBee Android SMS Gateway ──────────────────────────────
  if (textbeeApiKey && textbeeDeviceId) {
    const cleanBaseUrl = textbeeBaseUrl.replace(/\/+$/, '');
    const endpoint = `${cleanBaseUrl}/gateway/devices/${textbeeDeviceId}/send-sms`;

    console.log(`[SMS DIAGNOSTIC] TextBee sending SMS to: ${to.replace(/\d(?=\d{4})/g, '*')}`);

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 10000); // 10-second timeout

    try {
      const response = await fetch(endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-api-key': textbeeApiKey.trim()
        },
        body: JSON.stringify({
          recipients: [to],
          message: message
        }),
        signal: controller.signal
      });

      clearTimeout(timeoutId);

      let resData = {};
      try {
        resData = await response.json();
      } catch (_) {}

      console.log(`[SMS DIAGNOSTIC] TextBee HTTP Status: ${response.status}`);

      if (!response.ok) {
        console.error(`[SMS DIAGNOSTIC] TextBee Error ${response.status}:`, resData);

        if (response.status === 401 || response.status === 403) {
          throw new Error('SMS service authentication failed. Please try again or use Email verification.');
        }
        if (response.status === 404) {
          throw new Error('SMS gateway device unavailable. Please try again or use Email verification.');
        }
        if (response.status === 429) {
          throw new Error('SMS rate limit exceeded. Please wait a moment or use Email verification.');
        }
        throw new Error('Unable to send OTP right now. Please try again or use Email verification.');
      }

      // Check payload for specific TextBee failure states (e.g., success: false, device offline)
      if (resData.success === false || resData.error || (resData.data && resData.data.status === 'FAILED')) {
        console.error('[SMS DIAGNOSTIC] TextBee Payload Error:', resData);
        throw new Error('Unable to send OTP right now. Please try again or use Email verification.');
      }

      console.log('[SMS DIAGNOSTIC] TextBee SMS request successfully accepted by gateway.');
      return {
        provider: 'TextBee',
        status: 'SUCCESS',
        data: resData
      };

    } catch (err) {
      clearTimeout(timeoutId);
      if (err.name === 'AbortError') {
        console.error('[SMS DIAGNOSTIC] TextBee Request Timed Out (10s limit)');
        throw new Error('Unable to send OTP right now. Please try again or use Email verification.');
      }
      if (err.message.includes('Unable to send OTP') || err.message.includes('SMS gateway') || err.message.includes('SMS service') || err.message.includes('rate limit')) {
        throw err;
      }
      console.error('[SMS DIAGNOSTIC] TextBee Exception:', err.message);
      throw new Error('Unable to send OTP right now. Please try again or use Email verification.');
    }
  }

  // ── Strategy 2: Twilio Fallback ─────────────────────────────────────────
  const twilioSid   = process.env.TWILIO_ACCOUNT_SID;
  const twilioToken = process.env.TWILIO_AUTH_TOKEN;
  const twilioFrom  = process.env.TWILIO_PHONE_NUMBER;

  if (twilioSid && twilioToken && twilioFrom) {
    const url = `https://api.twilio.com/2010-04-01/Accounts/${twilioSid}/Messages.json`;
    const body = new URLSearchParams();
    body.append('To', to);
    body.append('From', twilioFrom);
    body.append('Body', message);

    console.log(`[SMS DIAGNOSTIC] Twilio sending SMS to: ${to.replace(/\d(?=\d{4})/g, '*')}`);

    let response;
    try {
      response = await fetch(url, {
        method: 'POST',
        headers: {
          'Authorization': 'Basic ' + Buffer.from(`${twilioSid}:${twilioToken}`).toString('base64'),
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: body.toString()
      });
    } catch (networkErr) {
      console.error('[SMS DIAGNOSTIC] Twilio Network Error:', networkErr.message);
      throw new Error('Unable to send OTP right now. Please try again or use Email verification.');
    }

    let resData = {};
    try {
      resData = await response.json();
    } catch (_) {}

    if (!response.ok) {
      console.error(`[SMS DIAGNOSTIC] Twilio Error ${response.status}:`, resData);
      throw new Error('Unable to send OTP right now. Please try again or use Email verification.');
    }

    console.log(`[SMS DIAGNOSTIC] Twilio SMS status: SUCCESS SID=${resData.sid}`);
    return {
      provider: 'Twilio',
      status: 'SUCCESS',
      sid: resData.sid || 'unknown'
    };
  }

  // Neither TextBee nor Twilio configured
  console.error('[SMS DIAGNOSTIC] SMS_NOT_CONFIGURED: No SMS provider credentials (TextBee or Twilio) found in environment.');
  throw new Error('SMS_NOT_CONFIGURED');
};

module.exports = sendSMS;
