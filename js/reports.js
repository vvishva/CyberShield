/**
 * CyberShield AI — Audit Reports Logic
 */

document.addEventListener('DOMContentLoaded', async () => {
  requireAuth();

  // Bind Back Button
  const backBtn = document.getElementById('btn-back-reports');
  if (backBtn) {
    backBtn.addEventListener('click', (e) => {
      e.preventDefault();
      if (window.history.length > 1) {
        window.history.back();
      } else {
        window.location.href = 'dashboard.html';
      }
    });
  }

  // Resolve scan data from URL query params or localStorage
  const urlParams = new URLSearchParams(window.location.search);
  const scanId = urlParams.get('id') || urlParams.get('scanId');

  let scan = null;

  if (scanId) {
    try {
      const res = await apiRequest('/scan/history');
      if (res.success && res.data) {
        scan = res.data.find(s => s._id === scanId || s.id === scanId);
      }
    } catch(e) {}
  }

  if (!scan) {
    const scanStr = localStorage.getItem('lastScanData');
    if (scanStr) {
      try {
        scan = JSON.parse(scanStr);
      } catch(e) {}
    }
  }
  
  if (scan) {
    renderReport(scan);
  } else {
    document.getElementById('rpt-empty').style.display = 'block';
  }

  const pdfBtn = document.getElementById('btn-generate-pdf');
  if (pdfBtn) {
    pdfBtn.addEventListener('click', (e) => {
      e.preventDefault();
      downloadPDF();
    });
  }
});

function downloadPDF() {
  const scanStr = localStorage.getItem('lastScanData');
  let params = {};
  if (scanStr) {
    try {
      const scan = JSON.parse(scanStr);
      params = { scanId: scan._id || scan.scanId, target: scan.target || scan.url, scanType: scan.scanType };
    } catch(e) {}
  }
  downloadReportPDF(params, 'CyberShield_Audit_Report.pdf');
}

window.downloadPDF = downloadPDF;

function renderReport(data) {
  document.getElementById('rpt-empty').style.display = 'none';
  document.getElementById('rpt-data').style.display = 'block';

  // Meta
  document.getElementById('rpt-id').textContent = 'CS-' + Math.random().toString(36).substr(2, 9).toUpperCase();
  document.getElementById('rpt-date').textContent = new Date().toLocaleString();
  
  const user = JSON.parse(localStorage.getItem('cybershield_user') || sessionStorage.getItem('cybershield_user') || '{}');
  document.getElementById('rpt-user').textContent = user.username || 'System Analyst';

  // Normalize: data may come from scanner (flat) or history (with .details)
  const details = data.details || data;
  const target = data.target || data.url || details.domain || 'Unknown Target';
  const status = data.status || data.riskLevel || details.riskLevel || 'Unknown';
  const riskScore = data.riskScore != null ? data.riskScore : (details.securityScore != null ? (100 - details.securityScore) : 0);
  const secScore = details.securityScore != null ? details.securityScore : (100 - (riskScore || 0));

  // Exec Summary
  document.getElementById('rpt-target').textContent = target;
  
  const vBadge = document.getElementById('rpt-verdict');
  vBadge.textContent = status;
  if (['Safe','Clean','Low Risk'].includes(status)) vBadge.style.color = 'var(--green)';
  else if (['Medium Risk'].includes(status)) vBadge.style.color = 'var(--amber)';
  else vBadge.style.color = 'var(--red)';

  document.getElementById('rpt-score').textContent = secScore + ' / 100';
  document.getElementById('rpt-conf').textContent = (data.confidenceScore || details.confidenceScore || 95) + '%';

  // Network checks
  const d = details;
  const netEl = document.getElementById('rpt-network');
  if (netEl) {
    netEl.innerHTML = `
      <tr>
        <td style="font-weight:600; width:30%;">HTTPS Validation</td>
        <td class="${d.hasHttps ? 'text-cyan' : ''}">${d.hasHttps ? 'Enabled - Secure channel established' : 'Disabled - Traffic sent in plaintext'}</td>
      </tr>
      <tr>
        <td style="font-weight:600;">Resolved IP</td>
        <td style="font-family:var(--font-mono);">${d.resolvedIp || 'N/A'}</td>
      </tr>
      <tr>
        <td style="font-weight:600;">Server Banner</td>
        <td class="${d.headerChecks?.serverBanner ? '' : 'text-cyan'}">${d.headerChecks?.serverBanner ? 'Disclosed - Potential information leak' : 'Hidden - Good security posture'}</td>
      </tr>
    `;
  }

  // Headers
  const h = d.headerChecks || {};
  const hdrEl = document.getElementById('rpt-headers');
  if (hdrEl) {
    hdrEl.innerHTML = `
      <tr><td style="font-weight:600; width:30%;">Strict-Transport-Security</td><td class="${h.hsts ? 'text-cyan' : ''}">${h.hsts ? 'Present' : 'Missing'}</td></tr>
      <tr><td style="font-weight:600;">Content-Security-Policy</td><td class="${h.csp ? 'text-cyan' : ''}">${h.csp ? 'Present' : 'Missing'}</td></tr>
      <tr><td style="font-weight:600;">X-Frame-Options</td><td class="${h.xFrameOptions ? 'text-cyan' : ''}">${h.xFrameOptions ? 'Present' : 'Missing'}</td></tr>
      <tr><td style="font-weight:600;">X-Content-Type-Options</td><td class="${h.xContentTypeOptions ? 'text-cyan' : ''}">${h.xContentTypeOptions ? 'Present' : 'Missing'}</td></tr>
      <tr><td style="font-weight:600;">Referrer-Policy</td><td class="${h.referrerPolicy ? 'text-cyan' : ''}">${h.referrerPolicy ? 'Present' : 'Missing'}</td></tr>
    `;
  }

  // Recommendations
  const recList = document.getElementById('rpt-recs');
  const recs = data.recommendations || d.recommendations || [];
  
  if (recList) {
    if (recs.length === 0) {
      recList.innerHTML = `<li style="list-style:none; color:var(--green);"><i class="fas fa-check"></i> Target conforms to primary security benchmarks. No immediate action required.</li>`;
    } else {
      recList.innerHTML = recs.map(r => `<li style="margin-bottom:10px;">${escapeHtml(r)}</li>`).join('');
    }
  }
}
