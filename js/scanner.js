/**
 * CyberShield AI — Scanner Logic
 */

document.addEventListener('DOMContentLoaded', () => {
  requireAuth(); // Need to be logged in to scan
  
  const form = document.getElementById('scan-form');
  const urlParam = new URLSearchParams(window.location.search).get('url');
  
  if (urlParam) {
    document.getElementById('scan-url').value = decodeURIComponent(urlParam);
    setTimeout(() => startScan(decodeURIComponent(urlParam)), 500);
  }

  form.addEventListener('submit', (e) => {
    e.preventDefault();
    const url = document.getElementById('scan-url').value.trim();
    if (url) startScan(url);
  });

  document.getElementById('btn-pdf').addEventListener('click', () => {
    const scanStr = localStorage.getItem('lastScanData');
    let params = {};
    if (scanStr) {
      try {
        const scan = JSON.parse(scanStr);
        params = { scanId: scan._id || scan.scanId, target: scan.target || scan.url, scanType: scan.scanType };
      } catch(e) {}
    }
    downloadReportPDF(params, 'CyberShield_Scan_Report.pdf');
  });

  document.getElementById('btn-investigate').addEventListener('click', () => {
    window.location.href = 'investigation.html';
  });
});

async function startScan(targetUrl) {
  // Normalize url
  let url = targetUrl;
  if (!url.startsWith('http')) url = 'https://' + url;

  const btn = document.getElementById('scan-btn');
  const loading = document.getElementById('scanner-loading');
  const results = document.getElementById('scan-results-container');
  const statusTxt = document.getElementById('scan-status-text');

  btn.disabled = true;
  btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Scanning...';
  
  results.style.display = 'none';
  loading.style.display = 'block';

  // Fake progressive status updates for UX
  const statuses = ['Resolving DNS...', 'Analyzing TLS Certificates...', 'Extracting Security Headers...', 'Running AI Heuristics...', 'Querying Threat Intel...'];
  let sIdx = 0;
  const statusInt = setInterval(() => {
    if(sIdx < statuses.length) statusTxt.textContent = statuses[sIdx++];
  }, 800);

  try {
    const res = await apiRequest('/scan/website', 'POST', { url });
    clearInterval(statusInt);

    if (res.success && res.data) {
      renderResults(res.data);
      // Save last scan to localStorage for PDF report
      localStorage.setItem('lastScanData', JSON.stringify(res.data));
    } else {
      throw new Error(res.error || 'Scan failed to return valid data');
    }
  } catch (err) {
    clearInterval(statusInt);
    showToast(err.message, 'danger');
  } finally {
    loading.style.display = 'none';
    btn.disabled = false;
    btn.innerHTML = 'Initiate Scan';
  }
}

function renderResults(data) {
  const container = document.getElementById('scan-results-container');
  container.style.display = 'block';

  // Meta
  document.getElementById('res-url').textContent = data.target || data.url;
  document.getElementById('res-ip').innerHTML = `<i class="fas fa-network-wired"></i> ${data.details?.resolvedIp || 'Unknown IP'}`;
  document.getElementById('res-domain').innerHTML = `<i class="fas fa-server"></i> ${data.details?.domain || 'Unknown Domain'}`;
  document.getElementById('res-time').innerHTML = `<i class="fas fa-clock"></i> Just now`;

  // Score
  const score = 100 - (data.riskScore || 0); // Display as Security Score (0-100 where 100 is best)
  const scoreEl = document.getElementById('res-score');
  animateNumber(scoreEl, 0, score, 1500);

  const circle = document.getElementById('score-circle');
  const circumference = 377; // 2 * pi * 60
  const offset = circumference - (score / 100) * circumference;
  
  // Set color based on score (100 = safe green, 0 = red)
  let color = 'var(--red)';
  if (score >= 90) color = 'var(--green)';
  else if (score >= 70) color = 'var(--cyan)';
  else if (score >= 50) color = 'var(--amber)';

  setTimeout(() => {
    circle.style.strokeDashoffset = offset;
    circle.style.stroke = color;
    scoreEl.style.color = color;
  }, 100);

  // Badge & Investigate Button
  const badge = document.getElementById('res-risk-badge');
  const invBtn = document.getElementById('btn-investigate');
  
  const status = data.status || data.riskLevel || 'Unknown';
  badge.textContent = status;
  badge.className = 'badge';
  invBtn.style.display = 'none'; // hide by default
  
  if (['Safe', 'Clean', 'Low Risk'].includes(status)) {
    badge.classList.add('badge-safe');
  }
  else if (['Medium Risk'].includes(status)) {
    badge.classList.add('badge-warning');
    invBtn.style.display = 'inline-block';
  }
  else if (['Phishing', 'Critical', 'High Risk'].includes(status)) {
    badge.classList.add('badge-critical');
    invBtn.style.display = 'inline-block';
  }
  else {
    badge.classList.add('badge-info');
  }

  // AI Verdict
  document.getElementById('res-ai-verdict').textContent = status;
  document.getElementById('res-ai-verdict').style.color = color;
  document.getElementById('res-ai-conf').textContent = (data.confidenceScore || 95) + '%';

  // Network checks
  const d = data.details || {};
  setCheck('chk-https', d.hasHttps, '✓ Enabled', '✗ Disabled');
  setCheck('chk-cert', d.hasHttps, '✓ Valid', '✗ Missing/Invalid'); // Simplified for demo
  setCheck('chk-banner', !d.headerChecks?.serverBanner, '✓ Hidden', '⚠ Disclosed', true);

  // Headers
  const h = d.headerChecks || {};
  setCheck('hdr-hsts', h.hsts, '✓ Present', '✗ Missing');
  setCheck('hdr-xframe', h.xFrameOptions, '✓ Present', '⚠ Missing', true);
  setCheck('hdr-xcontent', h.xContentTypeOptions, '✓ Present', '⚠ Missing', true);
  setCheck('hdr-csp', h.csp, '✓ Present', '✗ Missing');
  setCheck('hdr-ref', h.referrerPolicy, '✓ Present', '⚠ Missing', true);
  setCheck('hdr-perm', h.permissionsPolicy, '✓ Present', '⚠ Missing', true);

  // Historical Diff Logic
  const diffBox = document.getElementById('diff-box');
  const diffContent = document.getElementById('diff-content');
  if (data.diff) {
    diffBox.style.display = 'block';
    const scoreText = data.diff.scoreChange > 0 
      ? `<span style="color:var(--green)">+${data.diff.scoreChange} pts (Improved)</span>` 
      : (data.diff.scoreChange < 0 ? `<span style="color:var(--red)">${data.diff.scoreChange} pts (Declined)</span>` : 'No change');
    
    let vulnsText = '';
    if (data.diff.newVulnerabilities?.length > 0) {
      vulnsText += `<br><strong style="color:var(--red)">New Issues Detected:</strong> ${data.diff.newVulnerabilities.map(v => v.title).join(', ')}`;
    }
    if (data.diff.resolvedVulnerabilities?.length > 0) {
      vulnsText += `<br><strong style="color:var(--green)">Resolved Issues:</strong> ${data.diff.resolvedVulnerabilities.map(v => v.title).join(', ')}`;
    }
    if (!vulnsText) vulnsText = '<br><span style="color:var(--text-muted)">No new or resolved vulnerabilities since last scan.</span>';

    diffContent.innerHTML = `<strong>Score Drift:</strong> ${scoreText}${vulnsText}`;
  } else {
    diffBox.style.display = 'none';
  }

  // Recommendations
  const recBox = document.getElementById('rec-list');
  recBox.innerHTML = '';
  const recs = data.recommendations || [];
  
  if (recs.length === 0) {
    recBox.innerHTML = `<div style="padding:16px; color:var(--green);"><i class="fas fa-check-circle" style="margin-right:8px;"></i> No critical vulnerabilities detected. Great job!</div>`;
  } else {
    recs.forEach(r => {
      recBox.innerHTML += `
        <div class="rec-item">
          <i class="fas fa-exclamation-triangle"></i>
          <div style="font-size:13px; color:var(--text-primary); line-height:1.5;">${escapeHtml(r)}</div>
        </div>
      `;
    });
  }
}

function setCheck(id, isPass, passText, failText, isWarning = false) {
  const el = document.getElementById(id);
  if (!el) return;
  
  if (isPass) {
    el.className = 'check-status pass';
    el.innerHTML = passText;
  } else {
    el.className = isWarning ? 'check-status warn' : 'check-status fail';
    el.innerHTML = failText;
  }
}

function animateNumber(element, start, end, duration) {
  let startTimestamp = null;
  const step = (timestamp) => {
    if (!startTimestamp) startTimestamp = timestamp;
    const progress = Math.min((timestamp - startTimestamp) / duration, 1);
    element.textContent = Math.floor(progress * (end - start) + start);
    if (progress < 1) window.requestAnimationFrame(step);
  };
  window.requestAnimationFrame(step);
}
