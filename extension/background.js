/**
 * CyberShield Extension – Background Service Worker (MV3)
 * Handles auto-scan on navigation, tab switches, result caching, badge updates, and pause/resume.
 * Privacy: sends domain ONLY — never full URL path, query strings, or page content.
 */

const API_BASE = 'https://cybershield-backend-uhwn.onrender.com/api';

// Cache TTL constants
const CACHE_TTL_MS = 10 * 60 * 1000; // 10 min for chrome.storage.local (cross-restart)
const MEM_CACHE_TTL = 60 * 1000;      // 60 sec in-memory dedup guard

// Lightweight in-memory dedup — prevents hammering on same domain within 60s
const recentChecks = new Map();

// ---------------------------------------------------------------------------
// Alarm: periodic cache cleanup every 30 minutes
// ---------------------------------------------------------------------------
chrome.alarms.create('cleanupCache', { periodInMinutes: 30 });
chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === 'cleanupCache') {
    chrome.storage.local.get(null, (items) => {
      const now = Date.now();
      const toRemove = [];
      for (const [key, value] of Object.entries(items)) {
        if (key.startsWith('cs_') && value.ts && now - value.ts > CACHE_TTL_MS) {
          toRemove.push(key);
        }
      }
      if (toRemove.length) chrome.storage.local.remove(toRemove);
    });
    // Also clean memory map
    const now = Date.now();
    for (const [k, ts] of recentChecks.entries()) {
      if (now - ts > MEM_CACHE_TTL) recentChecks.delete(k);
    }
  }
});

// ---------------------------------------------------------------------------
// Core check & scan logic (shared across navigation, tab update, and tab switch)
// ---------------------------------------------------------------------------
async function checkAndScanUrl(url, tabId) {
  if (!url || !url.startsWith('http')) return; // skip chrome://, edge://, file://, etc.

  // Check pause state
  const prefs = await chrome.storage.local.get('protectionPaused');
  if (prefs.protectionPaused) {
    chrome.action.setBadgeText({ text: '⏸', tabId });
    chrome.action.setBadgeBackgroundColor({ color: '#555555', tabId });
    return;
  }

  let domain;
  let isHttps = false;
  try {
    const urlObj = new URL(url);
    domain = urlObj.hostname.replace(/^www\./, '');
    isHttps = urlObj.protocol === 'https:';
  } catch (_) { return; }

  // Skip private/local addresses (client-side guard)
  if (isPrivateDomain(domain)) return;

  const memKey = domain;
  const cacheKey = 'cs_' + domain;

  // In-memory dedup: same domain checked < 60s ago
  const lastCheck = recentChecks.get(memKey);
  if (lastCheck && Date.now() - lastCheck < MEM_CACHE_TTL) {
    const cached = await chrome.storage.local.get(cacheKey);
    if (cached[cacheKey]) {
      updateBadge(cached[cacheKey].result.outcome, tabId);
    }
    return;
  }

  // Check chrome.storage.local cache (10 min TTL)
  const cached = await chrome.storage.local.get(cacheKey);
  if (cached[cacheKey] && Date.now() - cached[cacheKey].ts < CACHE_TTL_MS) {
    recentChecks.set(memKey, Date.now());
    updateBadge(cached[cacheKey].result.outcome, tabId);
    return;
  }

  // Perform check
  recentChecks.set(memKey, Date.now());
  updateBadge('CHECKING', tabId);

  try {
    const res = await fetch(`${API_BASE}/extension/check`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ domain, isHttps })
    });
    const json = await res.json();

    if (json.success && json.data) {
      const result = json.data;
      await chrome.storage.local.set({ [cacheKey]: { result, ts: Date.now() } });
      updateBadge(result.outcome, tabId);
    } else {
      updateBadge('CHECK_FAILED', tabId);
    }
  } catch (err) {
    updateBadge('CHECK_FAILED', tabId);
  }
}

// ---------------------------------------------------------------------------
// 1. Navigation listener — fires immediately when top-level frame commits
// ---------------------------------------------------------------------------
chrome.webNavigation.onCommitted.addListener((details) => {
  if (details.frameId === 0) {
    checkAndScanUrl(details.url, details.tabId);
  }
});

// ---------------------------------------------------------------------------
// 2. Tab update listener — catches client-side routing & completed page loads
// ---------------------------------------------------------------------------
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete' && tab && tab.url) {
    checkAndScanUrl(tab.url, tabId);
  }
});

// ---------------------------------------------------------------------------
// 3. Tab switch listener — ensures badge is fresh when user switches tabs
// ---------------------------------------------------------------------------
chrome.tabs.onActivated.addListener(async (activeInfo) => {
  try {
    const tab = await chrome.tabs.get(activeInfo.tabId);
    if (tab && tab.url && tab.url.startsWith('http')) {
      checkAndScanUrl(tab.url, activeInfo.tabId);
    }
  } catch (_) {}
});

// ---------------------------------------------------------------------------
// Message handler — popup queries current tab result
// ---------------------------------------------------------------------------
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.action === 'getResult') {
    const cacheKey = 'cs_' + msg.domain;
    chrome.storage.local.get(cacheKey, (items) => {
      const entry = items[cacheKey];
      if (entry && Date.now() - entry.ts < CACHE_TTL_MS) {
        sendResponse({ success: true, result: entry.result, fromCache: true });
      } else {
        sendResponse({ success: false });
      }
    });
    return true; // async
  }

  if (msg.action === 'togglePause') {
    chrome.storage.local.get('protectionPaused', (prefs) => {
      const newState = !prefs.protectionPaused;
      chrome.storage.local.set({ protectionPaused: newState }, () => {
        sendResponse({ protectionPaused: newState });
      });
    });
    return true;
  }

  if (msg.action === 'getPauseState') {
    chrome.storage.local.get('protectionPaused', (prefs) => {
      sendResponse({ protectionPaused: !!prefs.protectionPaused });
    });
    return true;
  }

  if (msg.action === 'forceCheck') {
    // Popup requests a fresh check — clears cache then triggers check
    const cacheKey = 'cs_' + msg.domain;
    chrome.storage.local.remove(cacheKey, () => {
      recentChecks.delete(msg.domain);
      sendResponse({ success: true });
    });
    return true;
  }
});

// ---------------------------------------------------------------------------
// Badge helpers
// ---------------------------------------------------------------------------
function updateBadge(outcome, tabId) {
  const opts = tabId !== undefined ? { tabId } : {};
  switch (outcome) {
    case 'KNOWN_THREAT':
      chrome.action.setBadgeText({ text: '✕', ...opts });
      chrome.action.setBadgeBackgroundColor({ color: '#ef4444', ...opts });
      break;
    case 'SUSPICIOUS':
      chrome.action.setBadgeText({ text: '!', ...opts });
      chrome.action.setBadgeBackgroundColor({ color: '#f59e0b', ...opts });
      break;
    case 'NO_THREAT':
      chrome.action.setBadgeText({ text: '✓', ...opts });
      chrome.action.setBadgeBackgroundColor({ color: '#00c896', ...opts });
      break;
    case 'CHECK_FAILED':
      chrome.action.setBadgeText({ text: '?', ...opts });
      chrome.action.setBadgeBackgroundColor({ color: '#555555', ...opts });
      break;
    case 'CHECKING':
      chrome.action.setBadgeText({ text: '…', ...opts });
      chrome.action.setBadgeBackgroundColor({ color: '#00d4ff', ...opts });
      break;
    default:
      chrome.action.setBadgeText({ text: '', ...opts });
  }
}

// ---------------------------------------------------------------------------
// Client-side private domain guard (SSRF defence layer 1)
// ---------------------------------------------------------------------------
function isPrivateDomain(domain) {
  if (!domain) return true;
  const lower = domain.toLowerCase();
  if (lower === 'localhost') return true;
  if (lower.endsWith('.local') || lower.endsWith('.internal')) return true;
  // IPv4 private ranges
  const ipv4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(domain);
  if (ipv4) {
    const [, a, b] = ipv4.map(Number);
    if (a === 10) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 127) return true;
    if (a === 169 && b === 254) return true;
  }
  return false;
}
