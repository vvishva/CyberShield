/**
 * CyberShield Browser Extension — Production Background Service Worker & Script
 * 
 * Supports both:
 * - Microsoft Edge (Chromium MV3 Service Worker)
 * - Mozilla Firefox (Gecko MV3 Background Script)
 * 
 * Privacy: Transmits domain ONLY (never full URL paths, search queries, cookies, or page content).
 */

// Load dependencies if running in isolated worker context
if (typeof CYBERSHIELD_CONFIG === 'undefined' && typeof importScripts === 'function') {
  try {
    importScripts('../config/config.js', '../utils/browser-compat.js', '../utils/error-handler.js');
  } catch (e) {
    console.warn('[CyberShield Worker] importScripts fallback:', e.message);
  }
}

const config = globalThis.CYBERSHIELD_CONFIG || {
  API_BASE_URL: 'https://cybershield-backend-uhwn.onrender.com/api',
  CACHE_TTL_MS: 600000,
  MEM_CACHE_TTL_MS: 60000,
  REQUEST_TIMEOUT_MS: 15000
};

const bridge = globalThis.CyberShieldBridge || {
  raw: globalThis.chrome || globalThis.browser,
  storage: {
    get: (k) => (globalThis.chrome || globalThis.browser).storage.local.get(k),
    set: (v) => (globalThis.chrome || globalThis.browser).storage.local.set(v),
    remove: (k) => (globalThis.chrome || globalThis.browser).storage.local.remove(k)
  },
  action: {
    setBadgeText: (d) => (globalThis.chrome || globalThis.browser).action?.setBadgeText(d),
    setBadgeBackgroundColor: (d) => (globalThis.chrome || globalThis.browser).action?.setBadgeBackgroundColor(d)
  }
};

// In-memory deduplication map: domain -> timestamp
const memoryDedupMap = new Map();

// ---------------------------------------------------------------------------
// 1. Periodic Cache Cleanup Routine (every 30 minutes via alarms)
// ---------------------------------------------------------------------------
const rawAPI = bridge.raw;
if (rawAPI?.alarms) {
  rawAPI.alarms.create('cyberShieldCachePrune', { periodInMinutes: config.CLEANUP_ALARM_MINUTES || 30 });
  rawAPI.alarms.onAlarm.addListener(async (alarm) => {
    if (alarm.name === 'cyberShieldCachePrune') {
      try {
        const items = await bridge.storage.get(null);
        const now = Date.now();
        const toEvict = [];

        for (const [key, value] of Object.entries(items)) {
          if (key.startsWith('cs_') && value.ts && (now - value.ts > config.CACHE_TTL_MS)) {
            toEvict.push(key);
          }
        }

        if (toEvict.length > 0) {
          await bridge.storage.remove(toEvict);
        }

        // Clean memory map
        for (const [domain, ts] of memoryDedupMap.entries()) {
          if (now - ts > config.MEM_CACHE_TTL_MS) {
            memoryDedupMap.delete(domain);
          }
        }
      } catch (_) {}
    }
  });
}

// ---------------------------------------------------------------------------
// 2. Core Security Inspection Routine
// ---------------------------------------------------------------------------
async function checkAndScanUrl(url, tabId) {
  if (!url || !url.startsWith('http')) return; // ignore internal chrome://, edge://, about: pages

  // Respect user pause state
  try {
    const prefs = await bridge.storage.get('protectionPaused');
    if (prefs && prefs.protectionPaused) {
      updateBadge('PAUSED', tabId);
      return;
    }
  } catch (_) {}

  let domain;
  let isHttps = false;
  try {
    const parsed = new URL(url);
    domain = parsed.hostname.replace(/^www\./, '').toLowerCase();
    isHttps = parsed.protocol === 'https:';
  } catch (_) {
    return;
  }

  // Client-side privacy and SSRF guard — never send local/private domains
  if (isPrivateDomain(domain)) {
    updateBadge('SAFE', tabId);
    return;
  }

  const cacheKey = 'cs_' + domain;

  // Level 1: In-memory dedup (within 60s)
  const lastCheck = memoryDedupMap.get(domain);
  if (lastCheck && (Date.now() - lastCheck < config.MEM_CACHE_TTL_MS)) {
    try {
      const cached = await bridge.storage.get(cacheKey);
      if (cached && cached[cacheKey]) {
        updateBadge(cached[cacheKey].result.outcome, tabId);
        return;
      }
    } catch (_) {}
  }

  // Level 2: Persistent storage cache (within 10 minutes)
  try {
    const cached = await bridge.storage.get(cacheKey);
    if (cached && cached[cacheKey] && (Date.now() - cached[cacheKey].ts < config.CACHE_TTL_MS)) {
      memoryDedupMap.set(domain, Date.now());
      updateBadge(cached[cacheKey].result.outcome, tabId);
      return;
    }
  } catch (_) {}

  // Level 3: Live Scan through hardened CyberShield backend
  memoryDedupMap.set(domain, Date.now());
  updateBadge('CHECKING', tabId);

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), config.REQUEST_TIMEOUT_MS);

  try {
    const response = await fetch(`${config.API_BASE_URL}/extension/check`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
      },
      body: JSON.stringify({ domain, isHttps }),
      signal: controller.signal
    });

    clearTimeout(timeoutId);

    if (!response.ok) {
      throw new Error(`HTTP_${response.status}`);
    }

    const payload = await response.json();

    if (payload && payload.success && payload.data) {
      const result = payload.data;
      // Persist in local storage
      await bridge.storage.set({
        [cacheKey]: { result, ts: Date.now() }
      });

      updateBadge(result.outcome, tabId);

      // Trigger desktop notification for known threats
      if (result.outcome === 'KNOWN_THREAT') {
        notifyKnownThreat(domain, result.reason);
      }
    } else {
      updateBadge('CHECK_FAILED', tabId);
    }
  } catch (err) {
    clearTimeout(timeoutId);
    updateBadge('CHECK_FAILED', tabId);
  }
}

// ---------------------------------------------------------------------------
// 3. Proactive Desktop Security Warning
// ---------------------------------------------------------------------------
function notifyKnownThreat(domain, reason) {
  try {
    if (bridge.notifications && typeof bridge.notifications.create === 'function') {
      bridge.notifications.create(`threat_${domain}_${Date.now()}`, {
        type: 'basic',
        iconUrl: 'icons/icon128.png',
        title: '🚨 CyberShield Security Alert',
        message: `Dangerous website detected: ${domain}. ${reason || 'Do not input credentials or sensitive data.'}`,
        priority: 2
      });
    }
  } catch (_) {}
}

// ---------------------------------------------------------------------------
// 4. Navigation & Tab Lifecycle Event Listeners
// ---------------------------------------------------------------------------
// A. Top-level frame navigation
if (rawAPI?.webNavigation?.onCommitted) {
  rawAPI.webNavigation.onCommitted.addListener((details) => {
    if (details.frameId === 0 && details.url) {
      checkAndScanUrl(details.url, details.tabId);
    }
  });
}

// B. Tab loading completion (catches SPAs and standard document loads)
if (rawAPI?.tabs?.onUpdated) {
  rawAPI.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status === 'complete' && tab?.url) {
      checkAndScanUrl(tab.url, tabId);
    }
  });
}

// C. Tab activation (switching between open tabs updates badge instantly)
if (rawAPI?.tabs?.onActivated) {
  rawAPI.tabs.onActivated.addListener(async (activeInfo) => {
    try {
      if (rawAPI.tabs.get) {
        const tab = await rawAPI.tabs.get(activeInfo.tabId);
        if (tab?.url && tab.url.startsWith('http')) {
          checkAndScanUrl(tab.url, activeInfo.tabId);
        }
      }
    } catch (_) {}
  });
}

// ---------------------------------------------------------------------------
// 5. Popup & Runtime Communication Hub
// ---------------------------------------------------------------------------
if (rawAPI?.runtime?.onMessage) {
  rawAPI.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (msg.action === 'getResult') {
      const cacheKey = 'cs_' + msg.domain;
      bridge.storage.get(cacheKey).then((items) => {
        const entry = items ? items[cacheKey] : null;
        if (entry && (Date.now() - entry.ts < config.CACHE_TTL_MS)) {
          sendResponse({ success: true, result: entry.result, fromCache: true });
        } else {
          sendResponse({ success: false });
        }
      }).catch(() => sendResponse({ success: false }));
      return true; // async responder
    }

    if (msg.action === 'togglePause') {
      bridge.storage.get('protectionPaused').then((prefs) => {
        const newState = !Boolean(prefs && prefs.protectionPaused);
        bridge.storage.set({ protectionPaused: newState }).then(() => {
          sendResponse({ protectionPaused: newState });
        });
      }).catch(() => sendResponse({ protectionPaused: false }));
      return true;
    }

    if (msg.action === 'getPauseState') {
      bridge.storage.get('protectionPaused').then((prefs) => {
        sendResponse({ protectionPaused: Boolean(prefs && prefs.protectionPaused) });
      }).catch(() => sendResponse({ protectionPaused: false }));
      return true;
    }

    if (msg.action === 'forceCheck') {
      const cacheKey = 'cs_' + msg.domain;
      bridge.storage.remove(cacheKey).then(() => {
        memoryDedupMap.delete(msg.domain);
        sendResponse({ success: true });
      }).catch(() => sendResponse({ success: false }));
      return true;
    }
  });
}

// ---------------------------------------------------------------------------
// 6. Visual Badge System
// ---------------------------------------------------------------------------
function updateBadge(outcome, tabId) {
  const opts = (tabId !== undefined && tabId !== null) ? { tabId } : {};

  switch (outcome) {
    case 'KNOWN_THREAT':
      bridge.action.setBadgeText({ text: '✕', ...opts });
      bridge.action.setBadgeBackgroundColor({ color: '#ef4444', ...opts });
      break;
    case 'SUSPICIOUS':
      bridge.action.setBadgeText({ text: '!', ...opts });
      bridge.action.setBadgeBackgroundColor({ color: '#f59e0b', ...opts });
      break;
    case 'NO_THREAT':
    case 'SAFE':
      bridge.action.setBadgeText({ text: '✓', ...opts });
      bridge.action.setBadgeBackgroundColor({ color: '#00c896', ...opts });
      break;
    case 'CHECK_FAILED':
      bridge.action.setBadgeText({ text: '?', ...opts });
      bridge.action.setBadgeBackgroundColor({ color: '#555555', ...opts });
      break;
    case 'CHECKING':
      bridge.action.setBadgeText({ text: '…', ...opts });
      bridge.action.setBadgeBackgroundColor({ color: '#00d4ff', ...opts });
      break;
    case 'PAUSED':
      bridge.action.setBadgeText({ text: '⏸', ...opts });
      bridge.action.setBadgeBackgroundColor({ color: '#6b7280', ...opts });
      break;
    default:
      bridge.action.setBadgeText({ text: '', ...opts });
  }
}

// ---------------------------------------------------------------------------
// 7. Client-side Private Domain / SSRF Guard
// ---------------------------------------------------------------------------
function isPrivateDomain(domain) {
  if (!domain) return true;
  const lower = domain.toLowerCase();
  if (lower === 'localhost') return true;
  if (lower.endsWith('.local') || lower.endsWith('.internal')) return true;

  // RFC-1918 IPv4 check
  const ipv4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(domain);
  if (ipv4) {
    const [, a, b] = ipv4.map(Number);
    if (a === 10) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 127) return true;
    if (a === 169 && b === 254) return true;
    if (a === 0) return true;
  }
  return false;
}
