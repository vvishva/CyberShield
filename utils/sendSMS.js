/**
 * CyberShield — SMS Sender Utility
 *
 * Supported SMS Providers:
 *   1. Fast2SMS (Indian Cloud Gateway https://www.fast2sms.com)
 *   2. SMSGate (Official Android SMS Gateway https://sms-gate.app)
 *   3. TextBee Gateway (https://textbee.dev)
 *   4. Twilio Cloud Gateway (https://www.twilio.com)
 */

const { normalizePhoneNumber } = require('./phoneNormalizer');

/**
 * Check SMSGate message status via GET /message/{id}
 */
const checkSMSGateStatus = async (baseUrl, authHeader, messageId) => {
  const checkEndpoints = [
    `${baseUrl}/message/${messageId}`,
    `${baseUrl}/messages/${messageId}`
  ];

  for (const endpoint of checkEndpoints) {
    try {
      const res = await fetch(endpoint, {
        method: 'GET',
        headers: {
          'Authorization': authHeader,
          'Content-Type': 'application/json'
        }
      });
      if (!res.ok) continue;
      const json = await res.json();
      const state = json.state || json.status || null;
      const recipientErr = json.recipients?.[0]?.error || null;
      if (state) return { status: String(state).toUpperCase(), error: recipientErr, raw: json };
    } catch (_) {}
  }
  return null;
};

const sendSMS = async (to, message) => {
  // ── Strategy 1: Fast2SMS (Indian Cloud SMS Gateway https://www.fast2sms.com)
  const fast2smsApiKey = process.env.FAST2SMS_API_KEY;
  if (fast2smsApiKey && fast2smsApiKey.trim()) {
    const formattedPhone = normalizePhoneNumber(to, 'IN');
    const maskedPhone = formattedPhone.replace(/\d(?=\d{4})/g, '*');
    let local10Digits = formattedPhone;
    if (formattedPhone.startsWith('+91') && formattedPhone.length === 13) {
      local10Digits = formattedPhone.slice(3);
    }

    const endpoint = 'https://www.fast2sms.com/dev/bulkV2';
    console.log(`[Fast2SMS] Dispatching to recipient: ${maskedPhone} via ${endpoint}`);

    // Extract digits for OTP route if present, or fallback to quick route
    const digitsOnly = message.replace(/\D/g, '');
    const otpValue = digitsOnly.length >= 4 ? digitsOnly.substring(0, 6) : '123456';

    const payloads = [
      {
        route: 'otp',
        variables_values: otpValue,
        numbers: local10Digits
      },
      {
        route: 'q',
        message: message,
        language: 'english',
        flash: 0,
        numbers: local10Digits
      }
    ];

    let lastFast2SMSErr = null;

    for (const payload of payloads) {
      try {
        console.log(`[Fast2SMS] Trying route: ${payload.route}`);
        const response = await fetch(endpoint, {
          method: 'POST',
          headers: {
            'authorization': fast2smsApiKey.trim(),
            'Content-Type': 'application/json'
          },
          body: JSON.stringify(payload)
        });

        const responseText = await response.text();
        console.log(`[Fast2SMS] HTTP Status: ${response.status}`);
        console.log(`[Fast2SMS] Response snippet: ${responseText.substring(0, 300)}`);

        let resData = {};
        try { resData = JSON.parse(responseText); } catch (_) {}

        if (response.ok && resData.return !== false) {
          return {
            provider: 'Fast2SMS',
            status: 'SENT',
            smsBatchId: resData.request_id || 'fast2sms_sent',
            endpointUsed: endpoint,
            recipientMasked: maskedPhone
          };
        }

        const errMsg = resData.message || (resData.error ? JSON.stringify(resData.error) : responseText);
        lastFast2SMSErr = new Error(`Fast2SMS error (${payload.route}): ${errMsg}`);

      } catch (err) {
        lastFast2SMSErr = err;
      }
    }

    console.warn('[Fast2SMS] Both OTP & Quick routes returned error:', lastFast2SMSErr?.message);
    throw lastFast2SMSErr || new Error('Fast2SMS delivery failed');
  }

  // ── Strategy 2: SMSGate (Official Android SMS Gateway https://sms-gate.app)
  const smsgateLogin    = process.env.SMSGATEWAY_LOGIN;
  const smsgatePassword = process.env.SMSGATEWAY_PASSWORD;
  const smsgateToken    = process.env.SMSGATEWAY_TOKEN;
  const rawBaseUrl      = process.env.SMSGATEWAY_URL || 'https://api.sms-gate.app/3rdparty/v1';

  if (smsgateToken || (smsgateLogin && smsgatePassword)) {
    const formattedPhone = normalizePhoneNumber(to, 'IN');
    const maskedPhone = formattedPhone.replace(/\d(?=\d{4})/g, '*');

    let authHeader = '';
    if (smsgateToken) {
      authHeader = `Bearer ${smsgateToken.trim()}`;
    } else {
      authHeader = 'Basic ' + Buffer.from(`${smsgateLogin.trim()}:${smsgatePassword.trim()}`).toString('base64');
    }

    const cleanBaseUrl = rawBaseUrl.replace(/\/+$/, '');
    const endpoints = [
      `${cleanBaseUrl}/message`,
      `${cleanBaseUrl}/messages`
    ];

    const payload = {
      message: message,
      phoneNumbers: [formattedPhone],
      simNumber: 1
    };

    let lastError = null;

    for (const endpoint of endpoints) {
      console.log(`[SMSGate] Dispatching to recipient: ${maskedPhone} via ${endpoint}`);

      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 15000);

      try {
        const response = await fetch(endpoint, {
          method: 'POST',
          headers: {
            'Authorization': authHeader,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify(payload),
          signal: controller.signal
        });

        clearTimeout(timeoutId);

        const responseText = await response.text();
        console.log(`[SMSGate] HTTP Status: ${response.status}`);
        console.log(`[SMSGate] Response snippet: ${responseText.substring(0, 300)}`);

        let resData = {};
        try { resData = JSON.parse(responseText); } catch (_) {}

        if (!response.ok) {
          if (response.status === 401 || response.status === 403) {
            throw new Error('SMSGate authentication failed. Please check SMSGate credentials.');
          }
          if (response.status === 404) {
            lastError = new Error(`Endpoint 404: ${endpoint}`);
            continue;
          }
          throw new Error(`SMSGate HTTP error ${response.status}: ${resData.message || responseText}`);
        }

        const messageId = resData.id || resData._id || resData.messageId || null;
        let currentState = String(resData.state || resData.status || 'PENDING').toUpperCase();

        console.log(`[SMSGate] Message accepted. ID: ${messageId || 'N/A'}, Initial State: ${currentState}`);

        if (messageId) {
          for (let i = 0; i < 3; i++) {
            await new Promise(r => setTimeout(r, 1500));
            const statusResult = await checkSMSGateStatus(cleanBaseUrl, authHeader, messageId);
            if (statusResult) {
              currentState = statusResult.status;
              console.log(`[SMSGate] Status check #${i+1}: ${currentState}`);
              if (['FAILED', 'ERROR', 'REJECTED'].includes(currentState)) {
                const detailedError = statusResult.error ? ` (Carrier: ${statusResult.error})` : '';
                throw new Error(`SMSGate Android device reported message dispatch failure: ${currentState}${detailedError}`);
              }
              if (['SENT', 'DELIVERED', 'SUCCESS'].includes(currentState)) {
                break;
              }
            }
          }
        }

        return {
          provider: 'SMSGate',
          status: currentState,
          smsBatchId: messageId || 'accepted',
          endpointUsed: endpoint,
          recipientMasked: maskedPhone
        };

      } catch (err) {
        clearTimeout(timeoutId);
        lastError = err;
        if (err.message.includes('authentication failed')) throw err;
      }
    }

    if (lastError && !lastError.message.includes('dispatch failure')) {
      console.warn('[SMSGate] Dispatch failed. Checking secondary providers...');
    } else if (lastError) {
      throw lastError;
    }
  }

  // ── Strategy 3: TextBee Gateway ─────────────────────────────────────────
  const textbeeApiKey   = process.env.TEXTBEE_API_KEY;
  const textbeeDeviceId = process.env.TEXTBEE_DEVICE_ID;
  const textbeeBaseUrl  = process.env.TEXTBEE_API_BASE_URL || 'https://api.textbee.dev/api/v1';

  if (textbeeApiKey) {
    const cleanBaseUrl = textbeeBaseUrl.replace(/\/+$/, '');
    const formattedPhone = normalizePhoneNumber(to, 'IN');
    const maskedPhone = formattedPhone.replace(/\d(?=\d{4})/g, '*');

    let dispatchNumber = formattedPhone;
    if (formattedPhone.startsWith('+91') && formattedPhone.length === 13) {
      dispatchNumber = formattedPhone.slice(3);
    }

    const endpoint = textbeeDeviceId && textbeeDeviceId.trim()
      ? `${cleanBaseUrl}/gateway/devices/${textbeeDeviceId.trim()}/send-sms`
      : `${cleanBaseUrl}/gateway/send-sms`;

    const payload = {
      recipients: [dispatchNumber],
      message: message
    };

    const response = await fetch(endpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': textbeeApiKey.trim()
      },
      body: JSON.stringify(payload)
    });

    const responseText = await response.text();
    let resData = {};
    try { resData = JSON.parse(responseText); } catch (_) {}

    if (!response.ok) {
      throw new Error(`TextBee HTTP error ${response.status}: ${resData.message || responseText}`);
    }

    return {
      provider: 'TextBee',
      status: 'SENT',
      smsBatchId: resData.data?.smsBatchId || resData.smsBatchId || 'accepted',
      endpointUsed: endpoint,
      recipientMasked: maskedPhone
    };
  }

  // ── Strategy 4: Twilio Fallback ─────────────────────────────────────────
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

    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Authorization': 'Basic ' + Buffer.from(`${twilioSid}:${twilioToken}`).toString('base64'),
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: body.toString()
    });

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
