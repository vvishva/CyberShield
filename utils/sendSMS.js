/**
 * CyberShield — SMS Sender Utility & Delivery Status Tracker
 *
 * Supports TextBee SMS Gateway (Android App Gateway) as primary provider,
 * with optional Twilio fallback.
 * Credentials are read exclusively from environment variables.
 * The OTP value is NEVER logged or returned to the caller.
 *
 * TextBee Env Vars (set in Render dashboard):
 *   TEXTBEE_API_KEY              — API key generated from https://textbee.dev dashboard
 *   TEXTBEE_DEVICE_ID            — Unique device ID registered in TextBee app
 *   TEXTBEE_API_BASE_URL         — (Optional) Base API URL, defaults to https://api.textbee.dev/api/v1
 *   TEXTBEE_SIM_SUBSCRIPTION_ID  — (Optional) SIM slot index for dual-SIM phones (0 or 1)
 */

/**
 * Check TextBee batch status via GET /gateway/devices/{deviceId}/sms-batch/{smsBatchId}
 */
const checkTextBeeBatchStatus = async (baseUrl, deviceId, apiKey, batchId) => {
  const endpoint = `${baseUrl}/gateway/devices/${deviceId}/sms-batch/${batchId}`;
  try {
    const res = await fetch(endpoint, {
      method: 'GET',
      headers: {
        'x-api-key': apiKey.trim()
      }
    });
    if (!res.ok) return null;
    const json = await res.json();
    const batchData = json.data || json;
    const status = batchData.status || batchData.state || (batchData.success ? 'SENT' : null);
    return {
      status: status ? String(status).toUpperCase() : null,
      raw: batchData
    };
  } catch (err) {
    console.warn('[SMS DIAGNOSTIC] TextBee status check failed:', err.message);
    return null;
  }
};

/**
 * Fallback: Check message log via GET /gateway/devices/{deviceId}/messages
 */
const checkTextBeeMessagesStatus = async (baseUrl, deviceId, apiKey, recipientPhone) => {
  const endpoint = `${baseUrl}/gateway/devices/${deviceId}/messages?limit=10`;
  try {
    const res = await fetch(endpoint, {
      method: 'GET',
      headers: {
        'x-api-key': apiKey.trim()
      }
    });
    if (!res.ok) return null;
    const json = await res.json();
    const messages = (json.data && Array.isArray(json.data)) ? json.data : (Array.isArray(json) ? json : []);
    const match = messages.find(m => (m.recipients && m.recipients.includes(recipientPhone)) || m.recipient === recipientPhone);
    if (match) {
      return match.status ? String(match.status).toUpperCase() : 'SENT';
    }
    return null;
  } catch (_) {
    return null;
  }
};

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
  if (textbeeApiKey && textbeeDeviceId) {
    const cleanBaseUrl = textbeeBaseUrl.replace(/\/+$/, '');
    
    // Official non-deprecated endpoint: POST /gateway/send-sms with deviceId in body
    const endpoint = `${cleanBaseUrl}/gateway/send-sms`;

    // Normalize phone number into clean E.164 format (e.g. +919876543210)
    let formattedPhone = to.trim().replace(/[^\d+]/g, '');
    if (!formattedPhone.startsWith('+')) {
      formattedPhone = '+' + formattedPhone;
    }

    const maskedPhone = formattedPhone.replace(/\d(?=\d{4})/g, '*');
    const maskedDeviceId = textbeeDeviceId.length > 8 ? textbeeDeviceId.substring(0, 4) + '...' + textbeeDeviceId.slice(-4) : '****';

    console.log(`[SMS DIAGNOSTIC] TextBee sending request -> Device: ${maskedDeviceId}, Recipient: ${maskedPhone}`);

    const payload = {
      recipients: [formattedPhone],
      message: message,
      deviceId: textbeeDeviceId.trim()
    };

    // If dual SIM index is specified in env
    if (process.env.TEXTBEE_SIM_SUBSCRIPTION_ID !== undefined && process.env.TEXTBEE_SIM_SUBSCRIPTION_ID !== '') {
      payload.simSubscriptionId = parseInt(process.env.TEXTBEE_SIM_SUBSCRIPTION_ID, 10);
    }

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 10000); // 10s API timeout

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

      try {
        resData = await response.json();
      } catch (_) {}

      console.log(`[SMS DIAGNOSTIC] TextBee API HTTP Status: ${response.status}`);

      if (!response.ok) {
        console.error(`[SMS DIAGNOSTIC] TextBee API HTTP ${response.status} Error:`, JSON.stringify(resData));

        if (response.status === 401 || response.status === 403) {
          throw new Error('SMS gateway authentication failed. Please check TextBee API key or use Email verification.');
        }
        if (response.status === 404) {
          throw new Error('SMS gateway device not found. Please check TextBee Device ID or use Email verification.');
        }
        if (response.status === 429) {
          throw new Error('SMS rate limit exceeded. Please wait a moment or use Email verification.');
        }
        throw new Error('Unable to send OTP right now. Please try again or use Email verification.');
      }

      // Check top-level or nested success field
      const isAccepted = resData.success === true || (resData.data && resData.data.success === true) || response.status === 200 || response.status === 201;

      if (!isAccepted) {
        console.error('[SMS DIAGNOSTIC] TextBee API returned failure payload:', JSON.stringify(resData));
        throw new Error('Unable to send OTP right now. TextBee API rejected the SMS request.');
      }

      // 1. Capture returned SMS / batch ID safely
      const smsBatchId = resData.data?.smsBatchId || resData.smsBatchId || resData.data?._id || resData._id || resData.data?.id || resData.id;

      console.log(`[SMS DIAGNOSTIC] TextBee API accepted request. Batch ID: ${smsBatchId || 'N/A'}`);

      // 2. Track actual SMS delivery status on the Android gateway device
      let actualStatus = 'PENDING';

      if (smsBatchId) {
        // Poll status up to 3 times (with 2s intervals) to verify handoff to Android SIM card
        for (let attempt = 1; attempt <= 3; attempt++) {
          await new Promise(resolve => setTimeout(resolve, 2000));

          let checkResult = await checkTextBeeBatchStatus(cleanBaseUrl, textbeeDeviceId, textbeeApiKey, smsBatchId);
          if (!checkResult || !checkResult.status) {
            // Try message log fallback
            const msgStatus = await checkTextBeeMessagesStatus(cleanBaseUrl, textbeeDeviceId, textbeeApiKey, formattedPhone);
            if (msgStatus) checkResult = { status: msgStatus };
          }

          if (checkResult && checkResult.status) {
            actualStatus = checkResult.status;
            console.log(`[SMS DIAGNOSTIC] TextBee status check #${attempt} for batch ${smsBatchId}: ${actualStatus}`);

            if (['SENT', 'DELIVERED', 'SUCCESS'].includes(actualStatus)) {
              return {
                provider: 'TextBee',
                status: actualStatus,
                smsBatchId
              };
            }

            if (['FAILED', 'ERROR', 'REJECTED'].includes(actualStatus)) {
              console.error(`[SMS DIAGNOSTIC] TextBee reports FAILED for batch ${smsBatchId}`);
              throw new Error('SMS delivery failed on gateway device. Please ensure Android phone is active, online, and has SMS permissions.');
            }
          }
        }
      }

      // 3. Handle PENDING / QUEUED state after polling timeout
      // If still pending after 6+ seconds, the Android phone running TextBee is offline / not processing jobs
      if (['PENDING', 'QUEUED'].includes(actualStatus)) {
        console.error(`[SMS DIAGNOSTIC] TextBee batch ${smsBatchId || 'N/A'} still PENDING. Android phone appears offline or disconnected.`);
        throw new Error('Unable to send OTP right now. Android SMS gateway device appears offline. Please try again or use Email verification.');
      }

      return {
        provider: 'TextBee',
        status: actualStatus,
        smsBatchId
      };

    } catch (err) {
      clearTimeout(timeoutId);
      if (err.name === 'AbortError') {
        console.error('[SMS DIAGNOSTIC] TextBee API request timed out (10s limit)');
        throw new Error('Unable to send OTP right now. TextBee API timed out. Please try again or use Email verification.');
      }
      if (err.message.includes('Unable to send') || err.message.includes('SMS delivery failed') || err.message.includes('SMS gateway') || err.message.includes('rate limit')) {
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
    let formattedPhone = to.trim().replace(/[^\d+]/g, '');
    if (!formattedPhone.startsWith('+')) formattedPhone = '+' + formattedPhone;

    const url = `https://api.twilio.com/2010-04-01/Accounts/${twilioSid}/Messages.json`;
    const body = new URLSearchParams();
    body.append('To', formattedPhone);
    body.append('From', twilioFrom);
    body.append('Body', message);

    console.log(`[SMS DIAGNOSTIC] Twilio sending SMS to: ${formattedPhone.replace(/\d(?=\d{4})/g, '*')}`);

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
      console.error(`[SMS DIAGNOSTIC] Twilio Error ${response.status}:`, JSON.stringify(resData));
      throw new Error('Unable to send OTP right now. Please try again or use Email verification.');
    }

    console.log(`[SMS DIAGNOSTIC] Twilio SMS status: SENT SID=${resData.sid}`);
    return {
      provider: 'Twilio',
      status: 'SENT',
      smsBatchId: resData.sid || 'unknown'
    };
  }

  // Neither TextBee nor Twilio configured
  console.error('[SMS DIAGNOSTIC] SMS_NOT_CONFIGURED: No SMS provider credentials (TextBee or Twilio) found in environment.');
  throw new Error('SMS_NOT_CONFIGURED');
};

module.exports = sendSMS;
