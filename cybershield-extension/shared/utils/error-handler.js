/**
 * CyberShield Browser Extension — Production Error Handling Engine
 * 
 * Maps network issues, server status codes, cold starts, and runtime exceptions
 * into clear, professional, user-friendly security advisories.
 * NEVER leaks raw stack traces or internal server details to end users.
 */

(function (root) {
  'use strict';

  const ERROR_MESSAGES = {
    OFFLINE: 'No internet connection. CyberShield will resume monitoring once reconnected.',
    COLD_START: 'CyberShield security service is initializing. Retrying analysis...',
    TIMEOUT: 'Security check timed out. CyberShield service may be temporarily busy.',
    RATE_LIMITED: 'Rate limit reached. Requests are temporarily throttled to conserve resources.',
    SESSION_EXPIRED: 'Your session has expired. Please log in to your CyberShield dashboard again.',
    SERVER_ERROR: 'CyberShield security service is temporarily unavailable.',
    INVALID_URL: 'Unable to analyze this URL. Please verify the web address.',
    PARSING_ERROR: 'Unable to verify site security posture at this moment.',
    SAFE_BROWSING_FALLBACK: 'Threat database lookup temporarily delayed; heuristic protection active.',
    UNKNOWN: 'Security check could not be completed. Please try again later.'
  };

  /**
   * Translates any error object or HTTP status into a clean user-facing advisory
   * @param {Error|Response|string|any} error 
   * @param {string} [context] 
   * @returns {{ code: string, message: string, userFacing: boolean }}
   */
  function normalizeError(error, context) {
    // 1. Check network connectivity
    if (typeof navigator !== 'undefined' && navigator.onLine === false) {
      return { code: 'OFFLINE', message: ERROR_MESSAGES.OFFLINE, userFacing: true };
    }

    // 2. Fetch Response status checks
    if (error && typeof error.status === 'number') {
      if (error.status === 429) {
        return { code: 'RATE_LIMITED', message: ERROR_MESSAGES.RATE_LIMITED, userFacing: true };
      }
      if (error.status === 401 || error.status === 403) {
        return { code: 'SESSION_EXPIRED', message: ERROR_MESSAGES.SESSION_EXPIRED, userFacing: true };
      }
      if (error.status >= 500) {
        return { code: 'SERVER_ERROR', message: ERROR_MESSAGES.SERVER_ERROR, userFacing: true };
      }
    }

    // 3. Exception object inspection
    const msg = String(error?.message || error || '').toLowerCase();

    if (msg.includes('abort') || msg.includes('timeout') || msg.includes('timed out')) {
      return { code: 'TIMEOUT', message: ERROR_MESSAGES.TIMEOUT, userFacing: true };
    }

    if (msg.includes('failed to fetch') || msg.includes('networkerror') || msg.includes('network error')) {
      // Possible cold start on Render or temporary connectivity blip
      return { code: 'COLD_START', message: ERROR_MESSAGES.COLD_START, userFacing: true };
    }

    if (msg.includes('invalid url') || msg.includes('malformed')) {
      return { code: 'INVALID_URL', message: ERROR_MESSAGES.INVALID_URL, userFacing: true };
    }

    if (msg.includes('rate limit') || msg.includes('too many requests')) {
      return { code: 'RATE_LIMITED', message: ERROR_MESSAGES.RATE_LIMITED, userFacing: true };
    }

    if (msg.includes('auth') || msg.includes('token') || msg.includes('unauthorized')) {
      return { code: 'SESSION_EXPIRED', message: ERROR_MESSAGES.SESSION_EXPIRED, userFacing: true };
    }

    return { code: 'UNKNOWN', message: ERROR_MESSAGES.UNKNOWN, userFacing: true };
  }

  const CyberShieldErrorHandler = Object.freeze({
    MESSAGES: ERROR_MESSAGES,
    normalizeError,
    formatFriendlyMessage(err, context) {
      return normalizeError(err, context).message;
    }
  });

  root.CyberShieldErrorHandler = CyberShieldErrorHandler;
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = CyberShieldErrorHandler;
  }
})(typeof globalThis !== 'undefined' ? globalThis : this);
