const { parsePhoneNumberWithError } = require('libphonenumber-js');

/**
 * Normalizes any phone number into canonical E.164 format.
 * Defaults to 'IN' (India, +91) if no country code is present.
 *
 * Examples:
 *   "9876543210"     -> "+919876543210"
 *   "919876543210"   -> "+919876543210"
 *   "+919876543210"  -> "+919876543210"
 *   "09876543210"    -> "+919876543210"
 *
 * @param {string} phoneInput - Raw phone number string
 * @param {string} [defaultCountry='IN'] - Default 2-letter country code
 * @returns {string} Canonical E.164 phone number
 * @throws Error if phone number is invalid
 */
const normalizePhoneNumber = (phoneInput, defaultCountry = 'IN') => {
  if (!phoneInput || typeof phoneInput !== 'string') {
    throw new Error('Invalid phone number provided.');
  }

  let str = phoneInput.trim().replace(/[\s\-\(\)]/g, '');

  // If number starts with 91 followed by 10 digits (without +), prepend +
  if (/^91\d{10}$/.test(str)) {
    str = '+' + str;
  }

  try {
    const parsed = parsePhoneNumberWithError(str, defaultCountry);
    if (!parsed || !parsed.isValid()) {
      throw new Error('Invalid phone number format.');
    }
    return parsed.format('E.164');
  } catch (err) {
    if (!str.startsWith('+') && str.length > 10) {
      try {
        const retryParsed = parsePhoneNumberWithError('+' + str, defaultCountry);
        if (retryParsed && retryParsed.isValid()) {
          return retryParsed.format('E.164');
        }
      } catch (_) {}
    }
    throw new Error('Invalid phone number format. Please enter a valid mobile number.');
  }
};

module.exports = { normalizePhoneNumber };
