/**
 * CyberShield Browser Extension — Universal Browser Compatibility Layer
 * 
 * Provides unified, seamless API access across:
 * - Microsoft Edge (Chromium MV3: chrome.*)
 * - Mozilla Firefox (Gecko MV3: browser.* / chrome.*)
 */

(function (root) {
  'use strict';

  // Resolve native browser extension namespace
  const hasBrowser = typeof globalThis.browser !== 'undefined' && !!globalThis.browser.runtime;
  const hasChrome = typeof globalThis.chrome !== 'undefined' && !!globalThis.chrome.runtime;

  const rawAPI = hasBrowser ? globalThis.browser : (hasChrome ? globalThis.chrome : {});

  /**
   * Promisified wrapper for storage.local
   */
  const storage = {
    async get(keys) {
      if (hasBrowser && globalThis.browser.storage?.local?.get) {
        return globalThis.browser.storage.local.get(keys);
      }
      return new Promise((resolve, reject) => {
        try {
          rawAPI.storage.local.get(keys, (res) => {
            if (rawAPI.runtime.lastError) {
              return reject(new Error(rawAPI.runtime.lastError.message));
            }
            resolve(res || {});
          });
        } catch (err) {
          reject(err);
        }
      });
    },

    async set(items) {
      if (hasBrowser && globalThis.browser.storage?.local?.set) {
        return globalThis.browser.storage.local.set(items);
      }
      return new Promise((resolve, reject) => {
        try {
          rawAPI.storage.local.set(items, () => {
            if (rawAPI.runtime.lastError) {
              return reject(new Error(rawAPI.runtime.lastError.message));
            }
            resolve();
          });
        } catch (err) {
          reject(err);
        }
      });
    },

    async remove(keys) {
      if (hasBrowser && globalThis.browser.storage?.local?.remove) {
        return globalThis.browser.storage.local.remove(keys);
      }
      return new Promise((resolve, reject) => {
        try {
          rawAPI.storage.local.remove(keys, () => {
            if (rawAPI.runtime.lastError) {
              return reject(new Error(rawAPI.runtime.lastError.message));
            }
            resolve();
          });
        } catch (err) {
          reject(err);
        }
      });
    }
  };

  /**
   * Promisified wrapper for tabs
   */
  const tabs = {
    async query(queryInfo) {
      if (hasBrowser && globalThis.browser.tabs?.query) {
        return globalThis.browser.tabs.query(queryInfo);
      }
      return new Promise((resolve, reject) => {
        try {
          rawAPI.tabs.query(queryInfo, (res) => {
            if (rawAPI.runtime.lastError) return reject(new Error(rawAPI.runtime.lastError.message));
            resolve(res || []);
          });
        } catch (err) {
          reject(err);
        }
      });
    },

    async get(tabId) {
      if (hasBrowser && globalThis.browser.tabs?.get) {
        return globalThis.browser.tabs.get(tabId);
      }
      return new Promise((resolve, reject) => {
        try {
          rawAPI.tabs.get(tabId, (res) => {
            if (rawAPI.runtime.lastError) return reject(new Error(rawAPI.runtime.lastError.message));
            resolve(res);
          });
        } catch (err) {
          reject(err);
        }
      });
    },

    async create(createProperties) {
      if (hasBrowser && globalThis.browser.tabs?.create) {
        return globalThis.browser.tabs.create(createProperties);
      }
      return new Promise((resolve, reject) => {
        try {
          rawAPI.tabs.create(createProperties, (res) => {
            if (rawAPI.runtime.lastError) return reject(new Error(rawAPI.runtime.lastError.message));
            resolve(res);
          });
        } catch (err) {
          reject(err);
        }
      });
    }
  };

  /**
   * Action badge wrapper (handles action in MV3 or browserAction fallback)
   */
  const action = {
    setBadgeText(details) {
      if (rawAPI.action && typeof rawAPI.action.setBadgeText === 'function') {
        return rawAPI.action.setBadgeText(details);
      }
      if (rawAPI.browserAction && typeof rawAPI.browserAction.setBadgeText === 'function') {
        return rawAPI.browserAction.setBadgeText(details);
      }
    },

    setBadgeBackgroundColor(details) {
      if (rawAPI.action && typeof rawAPI.action.setBadgeBackgroundColor === 'function') {
        return rawAPI.action.setBadgeBackgroundColor(details);
      }
      if (rawAPI.browserAction && typeof rawAPI.browserAction.setBadgeBackgroundColor === 'function') {
        return rawAPI.browserAction.setBadgeBackgroundColor(details);
      }
    }
  };

  /**
   * Notifications wrapper
   */
  const notifications = {
    async create(notificationId, options) {
      if (!rawAPI.notifications?.create) return null;
      if (hasBrowser && globalThis.browser.notifications?.create) {
        return globalThis.browser.notifications.create(notificationId, options);
      }
      return new Promise((resolve) => {
        try {
          rawAPI.notifications.create(notificationId, options, (id) => {
            resolve(id);
          });
        } catch (_) {
          resolve(null);
        }
      });
    }
  };

  // Export unified CyberShield Browser Bridge
  const CyberShieldBridge = Object.freeze({
    raw: rawAPI,
    storage,
    tabs,
    action,
    notifications,
    runtime: rawAPI.runtime || {},
    alarms: rawAPI.alarms || {},
    webNavigation: rawAPI.webNavigation || {},
    isFirefox: hasBrowser || (navigator.userAgent && navigator.userAgent.includes('Firefox')),
    isEdge: navigator.userAgent && (navigator.userAgent.includes('Edg/') || navigator.userAgent.includes('Edge/'))
  });

  root.CyberShieldBridge = CyberShieldBridge;
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = CyberShieldBridge;
  }
})(typeof globalThis !== 'undefined' ? globalThis : this);
