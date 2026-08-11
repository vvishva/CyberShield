/**
 * CyberShield — SMS Sender Utility (TextBee Gateway)
 *
 * Supports sending via TextBee Android Gateway with exact Dashboard endpoint routing:
 *   If TEXTBEE_DEVICE_ID is set:
 *     POST https://api.textbee.dev/api/v1/gateway/devices/{deviceId}/send-sms
 *   Else:
 *     POST https://api.textbee.dev/api/v1/gateway/send-sms
 */

const sendSMS = async (to, message) => {
  const textbeeApiKey   = process.env.TEXTBEE_API_KEY;
  const textbeeDeviceId = process.env.TEXTBEE_DEVICE_ID;
  const textbeeBaseUrl  = process.env.TEXTBEE_API_BASE_URL || 'https://api.textbee.dev/api/v1';

  // ── Strategy 1: TextBee Android SMS Gateway ──────────────────────────────
  if (textbeeApiKey) {
    const cleanBaseUrl = textbeeBaseUrl.replace(/\/+$/, '');

    // Normalize phone number into clean E.164 format (e.g. +919876543210)
    let formattedPhone = to.trim().replace(/[\s\-\(\)]/g, '');
    if (!formattedPhone.startsWith('+')) {
      formattedPhone = '+' + formattedPhone;
    }

    const maskedPhone = formattedPhone.replace(/\d(?=\d{4})/g, '*');

    // Use device-scoped URL if device ID is set (matches TextBee Dashboard internal dispatch)
    let endpoint = `${cleanBaseUrl}/gateway/send-sms`;
    if (textbeeDeviceId && textbeeDeviceId.trim()) {
      endpoint = `${cleanBaseUrl}/gateway/devices/${textbeeDeviceId.trim()}/send-sms`;
    }

    console.log(`[SMS] Sending to: ${maskedPhone}`);
    console.log(`[SMS] Target Endpoint: ${endpoint}`);

    // Build payload matching TextBee Dashboard format
    const payload = {
      recipients: [formattedPhone],
      message: message
    };

    // Add deviceId to body as well for dual compatibility
    if (textbeeDeviceId && textbeeDeviceId.trim()) {
      payload.deviceId = textbeeDeviceId.trim();
    }

    // Add simSubscriptionId for dual-SIM phones if configured
    if (process.env.TEXTBEE_SIM_SUBSCRIPTION_ID !== undefined &&
        process.env.TEXTBEE_SIM_SUBSCRIPTION_ID !== '') {
      payload.simSubscriptionId = parseInt(process.env.TEXTBEE_SIM_SUBSCRIPTION_ID, 10);
    }

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

      const responseText = await response.text();
      console.log(`[SMS] HTTP Status: ${response.status}`);
      console.log(`[SMS] Response body: ${responseText.substring(0, 500)}`);

      try {
        resData = JSON.parse(responseText);
      } catch (_) {}

      if (!response.ok) {
        console.error(`[SMS] TextBee API error ${response.status}:`, responseText);

        if (response.status === 401 || response.status === 403) {
          throw new Error('SMS gateway authentication failed. Please check TextBee API key or use Email verification.');
        }
        if (response.status === 404) {
          throw new Error('SMS gateway device not found. Please check TextBee Device ID or use Email verification.');
        }
        if (response.status === 429) {
          throw new Error('SMS rate limit exceeded. Please wait a moment or use Email verification.');
        }
        throw new Error(`SMS gateway error (HTTP ${response.status}). Please try again or use Email verification.`);
      }

      const smsBatchId = resData.data?.smsBatchId
        || resData.smsBatchId
        || resData.data?._id
        || resData._id
        || resData.data?.id
        || resData.id
        || null;

      console.log(`[SMS] TextBee accepted request. Batch ID: ${smsBatchId || 'N/A'}`);

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
      throw new Error('Unable to send OTP right now. Please try again or use Email verification.');
    }

    let resData = {};
    try { resData = await response.json(); } catch (_) {}

    if (!response.ok) {
      throw new Error('Unable to send OTP right now. Please try again or use Email verification.');
    }

    return {
      provider: 'Twilio',
      status: 'SENT',
      smsBatchId: resData.sid || 'unknown'
    };
  }

  throw new Error('SMS_NOT_CONFIGURED');
};

module.exports = sendSMS;
