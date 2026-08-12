/**
 * CyberShield — SMS Sender Utility (TextBee Gateway)
 *
 * Integrates with TextBee Android SMS Gateway API.
 * Uses exact TextBee Dashboard dispatch format.
 */

const { normalizePhoneNumber } = require('./phoneNormalizer');

/**
 * Check TextBee status via GET /gateway/sms-batch/{smsBatchId}
 */
const checkTextBeeBatchStatus = async (baseUrl, deviceId, apiKey, batchId) => {
  const endpoints = [
    `${baseUrl}/gateway/sms-batch/${batchId}`
  ];
  if (deviceId && deviceId.trim()) {
    endpoints.unshift(`${baseUrl}/gateway/devices/${deviceId.trim()}/sms-batch/${batchId}`);
  }

  for (const endpoint of endpoints) {
    try {
      const res = await fetch(endpoint, {
        method: 'GET',
        headers: { 'x-api-key': apiKey.trim() }
      });
      if (!res.ok) continue;
      const json = await res.json();
      const batchData = json.data || json;
      const status = batchData.status || batchData.state || (batchData.success ? 'SENT' : null);
      if (status) return { status: String(status).toUpperCase(), raw: batchData };
    } catch (_) {}
  }
  return null;
};

const sendSMS = async (to, message) => {
  const textbeeApiKey   = process.env.TEXTBEE_API_KEY;
  const textbeeDeviceId = process.env.TEXTBEE_DEVICE_ID;
  const textbeeBaseUrl  = process.env.TEXTBEE_API_BASE_URL || 'https://api.textbee.dev/api/v1';

  // ── Strategy 1: TextBee Android SMS Gateway ──────────────────────────────
  if (textbeeApiKey) {
    const cleanBaseUrl = textbeeBaseUrl.replace(/\/+$/, '');

    // Canonicalize phone number into E.164 (+91XXXXXXXXXX)
    const formattedPhone = normalizePhoneNumber(to, 'IN');
    const maskedPhone = formattedPhone.replace(/\d(?=\d{4})/g, '*');

    // For Indian local SIM card sending via Android SmsManager,
    // convert +91XXXXXXXXXX to local 10-digit format (e.g. 9876543210) to match Dashboard manual send
    let dispatchNumber = formattedPhone;
    if (formattedPhone.startsWith('+91') && formattedPhone.length === 13) {
      dispatchNumber = formattedPhone.slice(3); // 10 digits: 9876543210
    }

    // Build endpoint priority list (Primary: /gateway/send-sms)
    const endpoints = [
      {
        url: `${cleanBaseUrl}/gateway/send-sms`,
        type: 'account-default'
      }
    ];

    if (textbeeDeviceId && textbeeDeviceId.trim()) {
      endpoints.push({
        url: `${cleanBaseUrl}/gateway/devices/${textbeeDeviceId.trim()}/send-sms`,
        type: 'device-scoped'
      });
    }

    // Build payload matching exact TextBee Dashboard manual send format
    const payload = {
      recipients: [dispatchNumber],
      message: message
    };

    if (process.env.TEXTBEE_SIM_SUBSCRIPTION_ID !== undefined &&
        process.env.TEXTBEE_SIM_SUBSCRIPTION_ID !== '') {
      payload.simSubscriptionId = parseInt(process.env.TEXTBEE_SIM_SUBSCRIPTION_ID, 10);
    }

    let lastError = null;

    for (const ep of endpoints) {
      console.log(`[SMS] Dispatching to local recipient: ${dispatchNumber.replace(/\d(?=\d{4})/g, '*')} (Canonical: ${maskedPhone}) via endpoint: ${ep.url}`);

      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 15000);

      try {
        const response = await fetch(ep.url, {
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
        console.log(`[SMS] Response snippet: ${responseText.substring(0, 300)}`);

        let resData = {};
        try { resData = JSON.parse(responseText); } catch (_) {}

        if (!response.ok) {
          if (response.status === 401 || response.status === 403) {
            throw new Error('SMS gateway authentication failed (HTTP 401/403). Please check TextBee API key.');
          }
          if (response.status === 404) {
            console.warn(`[SMS] Endpoint ${ep.url} returned 404. Trying next endpoint...`);
            lastError = new Error(`Device ID not found on endpoint ${ep.type}`);
            continue;
          }
          throw new Error(`SMS gateway HTTP error ${response.status}: ${resData.message || responseText}`);
        }

        const smsBatchId = resData.data?.smsBatchId
          || resData.smsBatchId
          || resData.data?._id
          || resData._id
          || resData.data?.id
          || resData.id
          || null;

        console.log(`[SMS] TextBee accepted request. Batch ID: ${smsBatchId || 'N/A'}`);

        // Status Check
        let actualStatus = 'SENT';
        if (smsBatchId) {
          for (let i = 0; i < 2; i++) {
            await new Promise(r => setTimeout(r, 1200));
            const checked = await checkTextBeeBatchStatus(cleanBaseUrl, textbeeDeviceId, textbeeApiKey, smsBatchId);
            if (checked) {
              actualStatus = checked.status;
              console.log(`[SMS] Status check #${i+1}: ${actualStatus}`);
              if (['FAILED', 'ERROR', 'REJECTED'].includes(actualStatus)) {
                throw new Error(`TextBee Android Gateway reported dispatch status: ${actualStatus}`);
              }
              if (['SENT', 'DELIVERED', 'SUCCESS'].includes(actualStatus)) {
                break;
              }
            }
          }
        }

        return {
          provider: 'TextBee',
          status: actualStatus,
          smsBatchId: smsBatchId || 'accepted',
          endpointUsed: ep.url,
          recipientMasked: maskedPhone,
          dispatchNumberMasked: dispatchNumber.replace(/\d(?=\d{4})/g, '*')
        };

      } catch (err) {
        clearTimeout(timeoutId);
        lastError = err;
        if (err.message.includes('authentication failed')) throw err;
      }
    }

    throw lastError || new Error('Unable to send SMS via TextBee Gateway.');
  }

  // ── Strategy 2: Twilio Fallback ─────────────────────────────────────────
  const twilioSid   = process.env.TWILIO_ACCOUNT_SID;
  const twilioToken = process.env.TWILIO_AUTH_TOKEN;
  const twilioFrom  = process.env.TWILIO_PHONE_NUMBER;

  if (twilioSid && twilioToken && twilioFrom) {
    const formattedPhone = normalizePhoneNumber(to, 'IN');

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
      throw new Error('Unable to send OTP right now. Network error.');
    }

    let resData = {};
    try { resData = await response.json(); } catch (_) {}

    if (!response.ok) {
      throw new Error('Twilio SMS delivery failed.');
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
