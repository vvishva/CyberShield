/**
 * CyberShield — Google OAuth 2.0 / Google Identity Services Token Verifier
 *
 * Uses `google-auth-library` native HTTP client for universal compatibility.
 * Supports verifying:
 *   1. Cryptographic ID Tokens (JWT) via verifyIdToken
 *   2. Access Tokens via UserInfo endpoint (client.request)
 *   3. Access Tokens via TokenInfo (client.getTokenInfo)
 */

const { OAuth2Client } = require('google-auth-library');

const verifyGoogleToken = async (tokenInput) => {
  if (!tokenInput || typeof tokenInput !== 'string') {
    throw new Error('Google authentication token is required.');
  }

  const cleanToken = tokenInput.trim();
  const clientId = process.env.GOOGLE_CLIENT_ID;
  const client = new OAuth2Client(clientId);

  // 1. Strategy 1: Official ID Token (JWT) verification
  try {
    const ticket = await client.verifyIdToken({
      idToken: cleanToken,
      audience: clientId || undefined
    });

    const payload = ticket.getPayload();
    if (payload && payload.email) {
      if (payload.email_verified === false) {
        throw new Error('Please use a verified Google account.');
      }
      return {
        googleId: payload.sub,
        email: payload.email.toLowerCase().trim(),
        emailVerified: true,
        name: payload.name || payload.given_name || payload.email.split('@')[0],
        picture: payload.picture || null,
        issuer: payload.iss
      };
    }
  } catch (sdkErr) {
    console.warn('[Google ID Token Verify]:', sdkErr.message);
  }

  // 2. Strategy 2: Google UserInfo Endpoint Verification (Access Token) via google-auth-library request
  try {
    const res = await client.request({
      url: 'https://www.googleapis.com/oauth2/v3/userinfo',
      headers: { Authorization: `Bearer ${cleanToken}` }
    });

    if (res && res.data && res.data.email) {
      const userInfo = res.data;
      if (userInfo.email_verified === false) {
        throw new Error('Please use a verified Google account.');
      }
      return {
        googleId: userInfo.sub,
        email: userInfo.email.toLowerCase().trim(),
        emailVerified: true,
        name: userInfo.name || userInfo.given_name || userInfo.email.split('@')[0],
        picture: userInfo.picture || null,
        issuer: 'https://accounts.google.com'
      };
    }
  } catch (uErr) {
    console.warn('[Google UserInfo Request]:', uErr.message);
  }

  // 3. Strategy 3: Google TokenInfo Verification via google-auth-library
  try {
    const tokenInfo = await client.getTokenInfo(cleanToken);
    if (tokenInfo && tokenInfo.email) {
      if (tokenInfo.email_verified === false) {
        throw new Error('Please use a verified Google account.');
      }
      return {
        googleId: tokenInfo.sub || tokenInfo.user_id,
        email: tokenInfo.email.toLowerCase().trim(),
        emailVerified: true,
        name: tokenInfo.email.split('@')[0],
        picture: null,
        issuer: 'https://accounts.google.com'
      };
    }
  } catch (tErr) {
    console.warn('[Google TokenInfo Verify]:', tErr.message);
  }

  throw new Error('Google authentication could not be verified.');
};

module.exports = { verifyGoogleToken };
