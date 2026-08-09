// Update this URL to match your deployed backend or localhost
const API_BASE = 'http://localhost:5000/api';

document.addEventListener('DOMContentLoaded', async () => {
  const loading = document.getElementById('loading-overlay');
  
  // Get active tab URL
  const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  const activeTab = tabs[0];
  const url = activeTab.url;
  
  // Exclude internal pages
  if (url.startsWith('chrome://') || url.startsWith('edge://') || url.startsWith('about:')) {
    document.getElementById('current-url').textContent = 'Internal Browser Page';
    document.getElementById('verdict-text').textContent = 'System Page';
    document.getElementById('verdict-text').className = 'verdict safe';
    loading.style.display = 'none';
    return;
  }
  
  try {
    const urlObj = new URL(url);
    document.getElementById('current-url').textContent = urlObj.hostname;
    
    // Check if we have a cached result in the background worker
    const cacheKey = 'scan_' + urlObj.hostname;
    const cache = await chrome.storage.local.get(cacheKey);
    
    if (cache[cacheKey]) {
      renderResults(cache[cacheKey]);
    } else {
      // Perform scan
      const res = await fetch(`${API_BASE}/scan/extension`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url })
      });
      
      const data = await res.json();
      if (data.success) {
        renderResults(data.data);
        // Cache result for 15 mins
        await chrome.storage.local.set({ [cacheKey]: { data: data.data, time: Date.now() } });
      } else {
        throw new Error(data.error);
      }
    }
  } catch (err) {
    document.getElementById('verdict-text').textContent = 'Scan Error';
    document.getElementById('verdict-text').className = 'verdict warning';
    document.getElementById('score-text').textContent = '!';
    console.error(err);
  } finally {
    loading.style.display = 'none';
  }
  
  document.getElementById('btn-report').addEventListener('click', () => {
    // Open full dashboard scanner page
    chrome.tabs.create({ url: `http://localhost:5000/client/scanner.html?url=${encodeURIComponent(url)}` });
  });
});

function renderResults(data) {
  const score = 100 - (data.riskScore || 0);
  document.getElementById('score-text').textContent = score;
  
  const circle = document.getElementById('score-progress');
  const offset = 251.2 - (score / 100) * 251.2;
  circle.style.strokeDashoffset = offset;
  
  const vText = document.getElementById('verdict-text');
  vText.textContent = data.status || 'Unknown';
  
  if (score >= 90) {
    circle.style.stroke = '#00c896';
    vText.className = 'verdict safe';
  } else if (score >= 50) {
    circle.style.stroke = '#f59e0b';
    vText.className = 'verdict warning';
  } else {
    circle.style.stroke = '#ef4444';
    vText.className = 'verdict danger';
  }
  
  document.getElementById('chk-https').textContent = data.isHttps ? 'Secure' : 'Insecure';
  document.getElementById('chk-https').className = data.isHttps ? 'chk-pass' : 'chk-fail';
  
  document.getElementById('chk-ai').textContent = data.status;
  document.getElementById('chk-ai').className = ['Safe', 'Clean'].includes(data.status) ? 'chk-pass' : 'chk-fail';
  
  document.getElementById('chk-conf').textContent = (data.confidence || 95) + '%';
  document.getElementById('chk-conf').className = 'chk-pass';
}
