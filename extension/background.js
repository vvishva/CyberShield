// CyberShield Extension Background Worker

const API_BASE = 'http://localhost:5000/api';
const CACHE_TTL = 15 * 60 * 1000; // 15 mins

// Clean up old cache periodically
chrome.alarms.create('cleanupCache', { periodInMinutes: 30 });
chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === 'cleanupCache') {
    chrome.storage.local.get(null, (items) => {
      const now = Date.now();
      const keysToRemove = [];
      for (const [key, value] of Object.entries(items)) {
        if (key.startsWith('scan_') && now - value.time > CACHE_TTL) {
          keysToRemove.push(key);
        }
      }
      if (keysToRemove.length > 0) chrome.storage.local.remove(keysToRemove);
    });
  }
});

// Auto-scan on tab load (optional feature, could be toggled by user)
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete' && tab.url && tab.url.startsWith('http')) {
    try {
      const urlObj = new URL(tab.url);
      const cacheKey = 'scan_' + urlObj.hostname;
      
      chrome.storage.local.get(cacheKey, async (cache) => {
        if (!cache[cacheKey] || Date.now() - cache[cacheKey].time > CACHE_TTL) {
          // Perform background scan
          try {
            const res = await fetch(`${API_BASE}/scan/extension`, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ url: tab.url })
            });
            const data = await res.json();
            if (data.success) {
              chrome.storage.local.set({ [cacheKey]: { data: data.data, time: Date.now() } });
              
              // Change extension badge based on risk
              updateBadge(data.data.status, tabId);
            }
          } catch(e) { console.error('BG scan err:', e); }
        } else {
          updateBadge(cache[cacheKey].data.status, tabId);
        }
      });
    } catch(e) {}
  }
});

function updateBadge(status, tabId) {
  let color = '#00c896'; // safe
  let text = '✓';
  if (['Phishing', 'Critical', 'High Risk'].includes(status)) {
    color = '#ef4444'; text = '!';
  } else if (status === 'Medium Risk') {
    color = '#f59e0b'; text = '!';
  }
  chrome.action.setBadgeBackgroundColor({ color, tabId });
  chrome.action.setBadgeText({ text, tabId });
}
