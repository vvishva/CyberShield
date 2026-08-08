/**
 * CyberShield AI — Security Scanner Logic
 */

const SCAN_STEPS = [
  'Initializing scan engine',
  'Validating URL structure',
  'Resolving domain DNS',
  'Checking SSL/TLS certificate',
  'Analyzing security headers',
  'Checking URL reputation (AI)',
  'Analyzing phishing indicators',
  'Generating security report'
];

let currentScanData = null;

function showScanProgress() {
  document.getElementById('scan-input-section').style.display = 'none';
  document.getElementById('scan-results-section').style.display = 'none';
  const progressEl = document.getElementById('scan-progress-section');
  progressEl.style.display = 'block';
  const stepsContainer = document.getElementById('scan-steps');
  stepsContainer.innerHTML = '';
  SCAN_STEPS.forEach((step, i) => {
    const el = document.createElement('div');
    el.className = 'scan-step' + (i === 0 ? ' active' : '');
    el.id = `step-${i}`;
    el.style.display = 'flex';
    el.style.alignItems = 'center';
    el.style.gap = '12px';
    el.style.opacity = i === 0 ? '1' : '0.5';
    el.innerHTML = `<span class="step-icon" style="color:var(--neon-cyan); width:24px; text-align:center;">${i===0 ? '<i class="fas fa-circle-notch fa-spin"></i>' : '<i class="far fa-circle"></i>'}</span><span class="step-text">${step}</span>`;
    stepsContainer.appendChild(el);
  });
  // Animate steps
  let current = 0;
  const interval = setInterval(() => {
    const prev = document.getElementById(`step-${current}`);
    if (prev) { 
      prev.style.opacity = '1'; 
      prev.querySelector('.step-icon').innerHTML = '<i class="fas fa-check-circle" style="color:var(--neon-green);"></i>'; 
    }
    current++;
    if (current < SCAN_STEPS.length) {
      const next = document.getElementById(`step-${current}`);
      if (next) {
        next.style.opacity = '1';
        next.querySelector('.step-icon').innerHTML = '<i class="fas fa-circle-notch fa-spin"></i>';
      }
    } else {
      clearInterval(interval);
    }
  }, 800);
  return interval;
}

function renderScanResults(websiteData, urlData) {
  document.getElementById('scan-progress-section').style.display = 'none';
  const resultsEl = document.getElementById('scan-results-section');
  resultsEl.style.display = 'block';
  
  // Use website scan data primarily, supplement with URL AI data
  const score = websiteData?.securityScore ?? (urlData ? (100 - (urlData.riskScore || 0)) : 50);
  const risk = websiteData?.riskLevel ?? urlData?.status ?? 'Unknown';
  
  // Score circle
  const scoreEl = document.getElementById('overall-score');
  if (scoreEl) scoreEl.textContent = score;
  const riskEl = document.getElementById('risk-level-badge');
  if (riskEl) {
    riskEl.textContent = risk;
    riskEl.className = 'badge ' + getRiskBadgeClass(risk);
  }
  
  // Color the score circle
  const scoreCircle = document.getElementById('score-circle');
  if (scoreCircle) {
    scoreCircle.style.borderColor = score >= 75 ? 'var(--neon-green)' : score >= 50 ? 'var(--neon-amber)' : 'var(--neon-red)';
    scoreCircle.style.boxShadow = `0 0 20px ${score >= 75 ? 'rgba(0,255,157,0.2)' : score >= 50 ? 'rgba(255,183,0,0.2)' : 'rgba(255,0,85,0.2)'}`;
  }
  
  // Score explanation
  const positives = [];
  const issues = [];
  if (websiteData?.hasHttps) positives.push('HTTPS enabled');
  else issues.push('No HTTPS encryption');
  if (websiteData?.headerChecks?.hsts) positives.push('HSTS header present');
  else issues.push('Missing HSTS header');
  if (websiteData?.headerChecks?.csp) positives.push('Content-Security-Policy set');
  else issues.push('Missing Content-Security-Policy');
  if (websiteData?.headerChecks?.xFrameOptions) positives.push('X-Frame-Options set');
  else issues.push('Missing X-Frame-Options');
  
  renderList('score-positives', positives, 'positive');
  renderList('score-issues', issues, 'issue');
  
  // Result cards
  setResultCard('result-ssl', websiteData?.hasHttps, websiteData?.hasHttps ? 'HTTPS enabled, certificate appears valid' : 'No SSL/TLS detected');
  setResultCard('result-headers', websiteData?.headerChecks ? Object.values(websiteData.headerChecks).filter(Boolean).length >= 3 : false, websiteData?.missingHeaders?.length > 0 ? `Missing: ${websiteData.missingHeaders.slice(0,2).join(', ')}...` : 'All major headers present');
  setResultCard('result-phishing', urlData?.status !== 'Phishing', urlData ? `AI Risk: ${urlData.riskScore || 0}% — ${urlData.status || 'Analyzed'}` : 'Structural analysis only');
  setResultCard('result-domain', !!websiteData?.domain, `Domain: ${websiteData?.domain || 'N/A'}`);
  setResultCard('result-url-rep', urlData?.status === 'Safe', urlData?.status || 'Unknown');
  setResultCard('result-server', !websiteData?.headerChecks?.serverBanner, websiteData?.headerChecks?.serverBanner ? 'Server banner exposed' : 'Server information protected');
  
  // Vulnerabilities
  const vulns = websiteData?.vulnerabilities || [];
  const vulnList = document.getElementById('vuln-list');
  if (vulnList) {
    if (vulns.length === 0) {
      vulnList.innerHTML = '<div style="padding:20px; text-align:center; background:rgba(0,255,157,0.05); border:1px solid rgba(0,255,157,0.2); border-radius:10px;"><i class="fas fa-shield-check" style="font-size:32px; color:var(--neon-green); margin-bottom:12px;"></i><p>No critical vulnerabilities detected</p></div>';
    } else {
      vulnList.innerHTML = vulns.map(v => `
        <div style="padding:16px; border-left:4px solid ${v.severity==='HIGH'?'var(--neon-red)':v.severity==='MEDIUM'?'var(--neon-amber)':'var(--neon-cyan)'}; background:rgba(255,255,255,0.03); margin-bottom:12px; border-radius:4px;">
          <div style="display:flex; justify-content:space-between; margin-bottom:8px;">
            <span style="font-weight:600;">${v.title}</span>
            <span class="badge badge-${v.severity === 'HIGH' ? 'danger' : v.severity === 'MEDIUM' ? 'warning' : 'info'}">${v.severity || 'INFO'}</span>
          </div>
          <p style="font-size:13px; color:var(--text-muted); margin-bottom:8px;">${v.description}</p>
          ${v.recommendation ? `<p style="font-size:12px; color:var(--neon-cyan);"><i class="fas fa-wrench"></i> Fix: ${v.recommendation}</p>` : ''}
        </div>
      `).join('');
    }
  }
  
  // Recommendations
  const recs = websiteData?.recommendations || [];
  renderList('rec-list', recs, 'rec');
  
  // Domain info
  setTextById('info-domain', websiteData?.domain || 'Data unavailable');
  setTextById('info-ip', websiteData?.resolvedIp || 'Data unavailable');
  setTextById('info-protocol', websiteData?.protocol || 'Data unavailable');
  const redirectChain = websiteData?.redirectChain || [];
  setTextById('info-redirects', redirectChain.length > 1 ? redirectChain.join(' → ') : 'No redirects detected');
  
  // Headers table
  const hChecks = websiteData?.headerChecks || {};
  const headerTableBody = document.getElementById('headers-table-body');
  if (headerTableBody) {
    const headerMap = [
      ['Strict-Transport-Security (HSTS)', hChecks.hsts],
      ['X-Frame-Options', hChecks.xFrameOptions],
      ['X-Content-Type-Options', hChecks.xContentTypeOptions],
      ['Content-Security-Policy', hChecks.csp],
      ['Referrer-Policy', hChecks.referrerPolicy],
      ['Permissions-Policy', hChecks.permissionsPolicy]
    ];
    headerTableBody.innerHTML = headerMap.map(([name, present]) => `
      <tr>
        <td>${name}</td>
        <td><span class="badge ${present ? 'badge-safe' : 'badge-danger'}">${present ? 'PRESENT' : 'MISSING'}</span></td>
        <td style="color:var(--text-muted); font-size:13px;">${present ? 'Configured properly' : 'Not set — configure this header'}</td>
      </tr>
    `).join('');
  }
  
  currentScanData = { websiteData, urlData, score, risk };
  resultsEl.scrollIntoView({ behavior: 'smooth' });
}

function setResultCard(id, passed, detail) {
  const el = document.getElementById(id);
  if (!el) return;
  const badge = el.querySelector('.result-status');
  const detailEl = el.querySelector('.result-detail');
  if (badge) {
    badge.textContent = passed ? 'PASS' : 'FAIL';
    badge.className = 'result-status badge ' + (passed ? 'badge-safe' : 'badge-danger');
  }
  if (detailEl) detailEl.textContent = detail || '';
}

function getRiskBadgeClass(risk) {
  if (risk === 'Safe') return 'badge-safe';
  if (risk === 'Low Risk') return 'badge-info';
  if (risk === 'Medium Risk') return 'badge-warning';
  if (risk === 'High Risk' || risk === 'Phishing') return 'badge-danger';
  if (risk === 'Critical') return 'badge-critical';
  return 'badge-info';
}

function renderList(id, items, type) {
  const el = document.getElementById(id);
  if (!el) return;
  if (!items || items.length === 0) { el.innerHTML = '<li style="color:var(--text-dim);"><i class="fas fa-minus"></i> None</li>'; return; }
  el.innerHTML = items.map(item => {
    const icon = type === 'positive' ? 'fa-check-circle' : type === 'issue' ? 'fa-times-circle' : 'fa-arrow-right';
    const color = type === 'positive' ? 'var(--neon-green)' : type === 'issue' ? 'var(--neon-red)' : 'var(--neon-cyan)';
    return `<li style="margin-bottom:8px;"><i class="fas ${icon}" style="color:${color}; margin-right:8px; width:16px;"></i> ${item}</li>`;
  }).join('');
}

function setTextById(id, text) {
  const el = document.getElementById(id);
  if (el) el.textContent = text;
}

function showInputSection() {
  document.getElementById('scan-progress-section').style.display = 'none';
  document.getElementById('scan-results-section').style.display = 'none';
  document.getElementById('scan-input-section').style.display = 'block';
  document.getElementById('scan-url-input').value = '';
}

document.addEventListener('DOMContentLoaded', () => {
  const scanBtn = document.getElementById('scan-btn');
  const urlInput = document.getElementById('scan-url-input');
  const scanAgainBtn = document.getElementById('scan-again-btn');
  
  if (scanAgainBtn) scanAgainBtn.addEventListener('click', showInputSection);
  
  async function startScan() {
    const url = urlInput?.value?.trim();
    if (!url) { showToast('Please enter a URL to scan', 'warning'); return; }
    
    // Basic URL format validation
    let targetUrl = url;
    if (!url.startsWith('http://') && !url.startsWith('https://')) targetUrl = 'https://' + url;
    
    const progressInterval = showScanProgress();
    
    try {
      // Run both scans in parallel
      const [websiteResult, urlResult] = await Promise.allSettled([
        apiRequest('/scan/website', 'POST', { url: targetUrl }),
        apiRequest('/scan/url', 'POST', { url: targetUrl })
      ]);
      
      clearInterval(progressInterval);
      
      const websiteData = websiteResult.status === 'fulfilled' && websiteResult.value.success ? websiteResult.value.data : null;
      const urlData = urlResult.status === 'fulfilled' && urlResult.value.success ? urlResult.value.data : null;
      
      if (!websiteData && !urlData) {
        throw new Error((websiteResult.value && websiteResult.value.error) || 'Both scan services returned errors');
      }
      
      // Mark all steps complete
      SCAN_STEPS.forEach((_, i) => {
        const step = document.getElementById(`step-${i}`);
        if (step) { 
          step.style.opacity = '1'; 
          step.querySelector('.step-icon').innerHTML = '<i class="fas fa-check-circle" style="color:var(--neon-green);"></i>'; 
        }
      });
      
      setTimeout(() => renderScanResults(websiteData, urlData), 500);
    } catch (err) {
      clearInterval(progressInterval);
      showInputSection();
      const errMsg = err.message?.includes('403') || err.message?.includes('Internal') ? 'Access to internal/private network resources is not permitted.' : 'Unable to complete the security scan. ' + (err.message || '');
      showToast(errMsg, 'danger');
    }
  }
  
  if (scanBtn) scanBtn.addEventListener('click', startScan);
  if (urlInput) urlInput.addEventListener('keypress', e => { if (e.key === 'Enter') startScan(); });
});
