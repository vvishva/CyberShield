/**
 * CyberShield — Google OAuth 2.0 / Google Identity Services Token Verifier
 *
 * Supports verifying:
 *   1. Cryptographic ID Tokens (JWT) via google-auth-library
 *   2. Access Tokens via Google UserInfo API (https://www.googleapis.com/oauth2/v3/userinfo)
 *   3. ID Tokens via Google Public TokenInfo API
 */

const { OAuth2Client } = require('google-auth-library');

const verifyGoogleToken = async (tokenInput) => {
  if (!tokenInput || typeof tokenInput !== 'string') {
    throw new Error('Google authentication token is required.');
  }

  const cleanToken = tokenInput.trim();
  const clientId = process.env.GOOGLE_CLIENT_ID;
  const client = new OAuth2Client(clientId);

  // Strategy 1: Official google-auth-library OAuth2Client verification (ID Token JWT)
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
    // SDK verify failed, proceed to UserInfo API
  }

  // Strategy 2: Google UserInfo Endpoint Verification (Access Token)
  try {
    const userInfoRes = await fetch('https://www.googleapis.com/oauth2/v3/userinfo', {
      headers: { Authorization: `Bearer ${cleanToken}` }
    });

    if (userInfoRes.ok) {
      const userInfo = await userInfoRes.json();
      if (userInfo.email) {
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
    }
  } catch (uErr) {}

  // Strategy 3: Google Public TokenInfo Endpoint Verification (ID Token Fallback)
  try {
    const response = await fetch(`https://oauth2.googleapis.com/tokeninfo?id_token=${encodeURIComponent(cleanToken)}`);
    if (response.ok) {
      const payload = await response.json();
      if (payload.email && !payload.error) {
        if (payload.email_verified === 'false' || payload.email_verified === false) {
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
    }
  } catch (tErr) {}

  throw new Error('Google authentication could not be verified.');
};

module.exports = { verifyGoogleToken };
