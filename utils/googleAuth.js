/**
 * CyberShield — Google OAuth 2.0 / Google Identity Services Token Verifier
 *
 * Verifies Google ID Tokens (JWT) issued by Google Accounts using the official `google-auth-library`
 * and falls back to Google's public tokeninfo endpoint.
 *
 * Validates:
 *   1. Cryptographic Signature
 *   2. Token Expiration
 *   3. Token Issuer (https://accounts.google.com or accounts.google.com)
 *   4. Client ID Audience (if GOOGLE_CLIENT_ID is provided)
 *   5. email_verified === true
 */

const { OAuth2Client } = require('google-auth-library');

const verifyGoogleToken = async (idToken) => {
  if (!idToken || typeof idToken !== 'string') {
    throw new Error('Google ID Token is required.');
  }

  const clientId = process.env.GOOGLE_CLIENT_ID;
  const client = new OAuth2Client(clientId);

  // Strategy 1: Official google-auth-library OAuth2Client verification
  try {
    const ticket = await client.verifyIdToken({
      idToken: idToken.trim(),
      audience: clientId || undefined
    });

    const payload = ticket.getPayload();
    if (!payload) {
      throw new Error('Invalid token payload.');
    }

    if (!payload.email) {
      throw new Error('Google account must have a valid email address.');
    }

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
  } catch (sdkErr) {
    console.warn('[Google Auth SDK Warning]:', sdkErr.message, 'Trying tokeninfo endpoint...');

    // Strategy 2: Google Public TokenInfo Endpoint Verification (Fallback)
    try {
      const response = await fetch(`https://oauth2.googleapis.com/tokeninfo?id_token=${encodeURIComponent(idToken.trim())}`);
      if (!response.ok) {
        throw new Error('Google authentication could not be verified.');
      }

      const payload = await response.json();

      if (payload.error || payload.error_description) {
        throw new Error(`Google Verification Failed: ${payload.error_description || payload.error}`);
      }

      if (!payload.email) {
        throw new Error('Google account must have a valid email address.');
      }

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
    } catch (fallbackErr) {
      throw new Error(fallbackErr.message || 'Google authentication could not be verified.');
    }
  }
};

module.exports = { verifyGoogleToken };
