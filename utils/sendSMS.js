/**
 * CyberShield — SMS Sender Utility (SMSGate / Android SMS Gateway)
 *
 * Primary Provider: SMSGate (Official Android SMS Gateway https://github.com/android-sms-gateway)
 * Fallback Providers: TextBee Gateway, Twilio
 */

const { normalizePhoneNumber } = require('./phoneNormalizer');

/**
 * Check SMSGate message status via GET /message/{id}
 */
const checkSMSGateStatus = async (baseUrl, authHeader, messageId) => {
  try {
    const res = await fetch(`${baseUrl}/message/${messageId}`, {
      method: 'GET',
      headers: {
        'Authorization': authHeader,
        'Content-Type': 'application/json'
      }
    });
    if (!res.ok) return null;
    const json = await res.json();
    const state = json.state || json.status || null;
    return state ? String(state).toUpperCase() : null;
  } catch (_) {
    return null;
  }
};

const sendSMS = async (to, message) => {
  const smsgateLogin    = process.env.SMSGATEWAY_LOGIN;
  const smsgatePassword = process.env.SMSGATEWAY_PASSWORD;
  const smsgateToken    = process.env.SMSGATEWAY_TOKEN;
  const smsgateBaseUrl  = (process.env.SMSGATEWAY_URL || 'https://api.sms-gateway.app/v1').replace(/\/+$/, '');

  // ── Strategy 1: SMSGate (Official Android SMS Gateway) ─────────────────
  if (smsgateToken || (smsgateLogin && smsgatePassword)) {
    const formattedPhone = normalizePhoneNumber(to, 'IN');
    const maskedPhone = formattedPhone.replace(/\d(?=\d{4})/g, '*');

    // Build Authorization Header
    let authHeader = '';
    if (smsgateToken) {
      authHeader = `Bearer ${smsgateToken.trim()}`;
    } else {
      authHeader = 'Basic ' + Buffer.from(`${smsgateLogin.trim()}:${smsgatePassword.trim()}`).toString('base64');
    }

    const endpoint = `${smsgateBaseUrl}/message/send`;
    console.log(`[SMSGate] Dispatching to recipient: ${maskedPhone} via ${endpoint}`);

    const payload = {
      message: message,
      phoneNumbers: [formattedPhone]
    };

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
        throw new Error(`SMSGate HTTP error ${response.status}: ${resData.message || responseText}`);
      }

      const messageId = resData.id || resData._id || resData.messageId || null;
      let currentState = String(resData.state || resData.status || 'PENDING').toUpperCase();

      console.log(`[SMSGate] Message accepted. ID: ${messageId || 'N/A'}, Initial State: ${currentState}`);

      // Poll status if messageId available
      if (messageId) {
        for (let i = 0; i < 2; i++) {
          await new Promise(r => setTimeout(r, 1200));
          const statusResult = await checkSMSGateStatus(smsgateBaseUrl, authHeader, messageId);
          if (statusResult) {
            currentState = statusResult;
            console.log(`[SMSGate] Status check #${i+1}: ${currentState}`);
            if (['FAILED', 'ERROR', 'REJECTED'].includes(currentState)) {
              throw new Error(`SMSGate Android device reported message dispatch failure: ${currentState}`);
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
      console.error('[SMSGate Error]:', err.message);
      throw err;
    }
  }

  // ── Strategy 2: TextBee Gateway (Secondary Fallback) ───────────────────
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

  // ── Strategy 3: Twilio Fallback ─────────────────────────────────────────
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
