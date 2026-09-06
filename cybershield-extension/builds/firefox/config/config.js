/**
 * CyberShield Browser Extension — Centralized Production Configuration
 * 
 * Target environments: Microsoft Edge Add-ons & Mozilla Firefox Add-ons
 * ZERO secrets or local IP addresses are stored here.
 * All threat intelligence and security scans route through the hardened CyberShield backend.
 */

const CYBERSHIELD_CONFIG = Object.freeze({
  // Production Backend & SOC Dashboard Endpoints
  API_BASE_URL: 'https://cybershield-backend-uhwn.onrender.com/api',
  DASHBOARD_URL: 'https://cybershield-backend-uhwn.onrender.com',

  // Extension Details
  NAME: 'CyberShield AI Security',
  VERSION: '2.1.0',
  DESCRIPTION: 'Real-time AI-powered web security monitoring and phishing detection.',

  // Cache & Timing Configurations
  CACHE_TTL_MS: 10 * 60 * 1000,   // 10 minutes local persistent cache (storage.local)
  MEM_CACHE_TTL_MS: 60 * 1000,    // 60 seconds in-memory deduplication
  CLEANUP_ALARM_MINUTES: 30,      // Periodic background cache cleanup frequency

  // Network & Cold Start Tolerances (Render backend cold-start resilience)
  REQUEST_TIMEOUT_MS: 15000,      // 15 seconds request timeout
  MAX_RETRY_ATTEMPTS: 2,          // Transient retry limit for waking backend

  // Rate Limiter Awareness (matches backend 30 checks per 5 mins)
  MAX_HOURLY_CHECKS: 360,

  // Support & Documentation Links
  SUPPORT_EMAIL: 'support@cybershield.io',
  PRIVACY_POLICY_URL: 'https://cybershield-backend-uhwn.onrender.com/client/privacy.html',
  DOCUMENTATION_URL: 'https://cybershield-backend-uhwn.onrender.com/client/reports.html'
});

// Expose globally for both service worker & script environments
if (typeof globalThis !== 'undefined') {
  globalThis.CYBERSHIELD_CONFIG = CYBERSHIELD_CONFIG;
}
if (typeof module !== 'undefined' && module.exports) {
  module.exports = CYBERSHIELD_CONFIG;
}
