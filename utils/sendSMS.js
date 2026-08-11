/**
 * CyberShield — SMS Sender Utility (TextBee Gateway)
 *
 * Uses the OFFICIAL TextBee API contract exactly as documented at:
 *   https://textbee.dev/docs/sending-sms/sending-sms
 *
 * Endpoint: POST https://api.textbee.dev/api/v1/gateway/send-sms
 * Headers:  Content-Type: application/json, x-api-key: YOUR_API_KEY
 * Body:     { "recipients": ["+1234567890"], "message": "Hello" }
 *
 * IMPORTANT: The official docs do NOT pass deviceId in body.
 *   By default TextBee uses "your default device, or your most recently
 *   active enabled device" — exactly what the dashboard does.
 *
 * TextBee Env Vars (set in Render dashboard):
 *   TEXTBEE_API_KEY              — API key from https://textbee.dev dashboard
 *   TEXTBEE_DEVICE_ID            — (Optional) Only needed for multi-device accounts
 *   TEXTBEE_API_BASE_URL         — (Optional) defaults to https://api.textbee.dev/api/v1
 *   TEXTBEE_SIM_SUBSCRIPTION_ID  — (Optional) SIM slot for dual-SIM phones (0 or 1)
 */

/**
 * Send an SMS via TextBee (or Twilio fallback).
 *
 * @param {string} to      - Recipient phone in E.164 format (e.g. +919876543210)
 * @param {string} message - SMS body text
 * @returns {Promise<{ provider: string, status: string, smsBatchId?: string }>}
 * @throws  Error('SMS_NOT_CONFIGURED') if env vars are missing
 * @throws  Error with user-facing message on delivery failure
 */
const sendSMS = async (to, message) => {
  const textbeeApiKey   = process.env.TEXTBEE_API_KEY;
  const textbeeDeviceId = process.env.TEXTBEE_DEVICE_ID;
  const textbeeBaseUrl  = process.env.TEXTBEE_API_BASE_URL || 'https://api.textbee.dev/api/v1';

  // ── Strategy 1: TextBee Android SMS Gateway ──────────────────────────────
  if (textbeeApiKey) {
    const cleanBaseUrl = textbeeBaseUrl.replace(/\/+$/, '');

    // Official endpoint from docs: POST /gateway/send-sms
    const endpoint = `${cleanBaseUrl}/gateway/send-sms`;

    // Normalize phone number into clean E.164 format
    let formattedPhone = to.trim().replace(/[\s\-\(\)]/g, '');
    if (!formattedPhone.startsWith('+')) {
      formattedPhone = '+' + formattedPhone;
    }

    const maskedPhone = formattedPhone.replace(/\d(?=\d{4})/g, '*');

    console.log(`[SMS] Sending to: ${maskedPhone}`);
    console.log(`[SMS] Endpoint: ${endpoint}`);

    // Build request body — match EXACTLY what the TextBee docs/dashboard sends
    const payload = {
      recipients: [formattedPhone],
      message: message
    };

    // Only add deviceId if explicitly configured (for multi-device accounts)
    if (textbeeDeviceId && textbeeDeviceId.trim()) {
      payload.deviceId = textbeeDeviceId.trim();
      const maskedId = textbeeDeviceId.length > 8
        ? textbeeDeviceId.substring(0, 4) + '...' + textbeeDeviceId.slice(-4)
        : '****';
      console.log(`[SMS] Using specific device: ${maskedId}`);
    } else {
      console.log(`[SMS] Using default/most-recent device (no deviceId specified)`);
    }

    // Add simSubscriptionId for dual-SIM phones if configured
    if (process.env.TEXTBEE_SIM_SUBSCRIPTION_ID !== undefined &&
        process.env.TEXTBEE_SIM_SUBSCRIPTION_ID !== '') {
      payload.simSubscriptionId = parseInt(process.env.TEXTBEE_SIM_SUBSCRIPTION_ID, 10);
      console.log(`[SMS] SIM slot: ${payload.simSubscriptionId}`);
    }

    console.log(`[SMS] Payload keys: ${Object.keys(payload).join(', ')}`);
    console.log(`[SMS] Recipients count: ${payload.recipients.length}`);
    console.log(`[SMS] Message length: ${payload.message.length} chars`);

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 15000); // 15s timeout

    let response;
    let resData = {};

    try {
      response = await fetch(endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-api-key': textbeeApiKey.trim()
        },
        body: JSON.stringify(payload),
        signal: controller.signal
      });

      clearTimeout(timeoutId);

      // Parse response body
      const responseText = await response.text();
      console.log(`[SMS] HTTP Status: ${response.status}`);
      console.log(`[SMS] Response body: ${responseText.substring(0, 500)}`);

      try {
        resData = JSON.parse(responseText);
      } catch (parseErr) {
        console.error(`[SMS] Failed to parse response as JSON`);
        resData = {};
      }

      // Handle HTTP errors
      if (!response.ok) {
        console.error(`[SMS] TextBee API error ${response.status}`);

        if (response.status === 401 || response.status === 403) {
          throw new Error('SMS gateway authentication failed. Please check TextBee API key or use Email verification.');
        }
        if (response.status === 404) {
          throw new Error('SMS gateway endpoint not found. Please check TextBee configuration or use Email verification.');
        }
        if (response.status === 429) {
          throw new Error('SMS rate limit exceeded. Please wait a moment or use Email verification.');
        }
        throw new Error(`SMS gateway error (HTTP ${response.status}). Please try again or use Email verification.`);
      }

      // HTTP 200/201 — TextBee accepted the request
      // Per TextBee docs, this means the SMS is queued for the Android device
      // This is the same behavior as sending from the TextBee Dashboard
      const smsBatchId = resData.data?.smsBatchId
        || resData.smsBatchId
        || resData.data?._id
        || resData._id
        || resData.data?.id
        || resData.id
        || null;

      console.log(`[SMS] TextBee accepted. Batch ID: ${smsBatchId || 'N/A'}`);
      console.log(`[SMS] Success field: ${resData.success}`);

      // If TextBee API returned HTTP 200, trust it — same as dashboard behavior
      // The SMS is queued and will be sent by the Android device
      return {
        provider: 'TextBee',
        status: 'QUEUED',
        smsBatchId: smsBatchId || 'accepted'
      };

    } catch (err) {
      clearTimeout(timeoutId);

      if (err.name === 'AbortError') {
        console.error('[SMS] TextBee API request timed out (15s)');
        throw new Error('SMS gateway timed out. Please try again or use Email verification.');
      }

      // Re-throw our own error messages
      if (err.message.includes('SMS gateway') ||
          err.message.includes('SMS rate') ||
          err.message.includes('Unable to send')) {
        throw err;
      }

      console.error('[SMS] Unexpected error:', err.message);
      throw new Error('Unable to send OTP right now. Please try again or use Email verification.');
    }
  }

  // ── Strategy 2: Twilio Fallback ─────────────────────────────────────────
  const twilioSid   = process.env.TWILIO_ACCOUNT_SID;
  const twilioToken = process.env.TWILIO_AUTH_TOKEN;
  const twilioFrom  = process.env.TWILIO_PHONE_NUMBER;

  if (twilioSid && twilioToken && twilioFrom) {
    let formattedPhone = to.trim().replace(/[\s\-\(\)]/g, '');
    if (!formattedPhone.startsWith('+')) formattedPhone = '+' + formattedPhone;

    const url = `https://api.twilio.com/2010-04-01/Accounts/${twilioSid}/Messages.json`;
    const body = new URLSearchParams();
    body.append('To', formattedPhone);
    body.append('From', twilioFrom);
    body.append('Body', message);

    console.log(`[SMS] Twilio sending to: ${formattedPhone.replace(/\d(?=\d{4})/g, '*')}`);

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
      console.error('[SMS] Twilio network error:', networkErr.message);
      throw new Error('Unable to send OTP right now. Please try again or use Email verification.');
    }

    let resData = {};
    try { resData = await response.json(); } catch (_) {}

    if (!response.ok) {
      console.error(`[SMS] Twilio error ${response.status}:`, JSON.stringify(resData));
      throw new Error('Unable to send OTP right now. Please try again or use Email verification.');
    }

    console.log(`[SMS] Twilio SMS queued. SID: ${resData.sid}`);
    return {
      provider: 'Twilio',
      status: 'SENT',
      smsBatchId: resData.sid || 'unknown'
    };
  }

  // Neither provider configured
  console.error('[SMS] SMS_NOT_CONFIGURED: No SMS provider credentials found.');
  throw new Error('SMS_NOT_CONFIGURED');
};

module.exports = sendSMS;
