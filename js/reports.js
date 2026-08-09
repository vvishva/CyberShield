/**
 * CyberShield AI — Audit Reports Logic
 */

document.addEventListener('DOMContentLoaded', () => {
  requireAuth();
  
  // Try to load last scan from local storage
  const scanStr = localStorage.getItem('lastScanData');
  
  if (scanStr) {
    try {
      const scan = JSON.parse(scanStr);
      renderReport(scan);
    } catch(e) {
      console.error(e);
      document.getElementById('rpt-empty').style.display = 'block';
    }
  } else {
    document.getElementById('rpt-empty').style.display = 'block';
  }
});

function renderReport(data) {
  document.getElementById('rpt-empty').style.display = 'none';
  document.getElementById('rpt-data').style.display = 'block';

  // Meta
  document.getElementById('rpt-id').textContent = 'CS-' + Math.random().toString(36).substr(2, 9).toUpperCase();
  document.getElementById('rpt-date').textContent = new Date().toLocaleString();
  
  const user = JSON.parse(localStorage.getItem('cybershield_user') || '{}');
  document.getElementById('rpt-user').textContent = user.username || 'System Analyst';

  // Exec Summary
  document.getElementById('rpt-target').textContent = data.target || data.url || 'Unknown Target';
  
  const vBadge = document.getElementById('rpt-verdict');
  vBadge.textContent = data.status || 'Unknown';
  if (['Safe','Clean'].includes(data.status)) vBadge.style.color = 'var(--green)';
  else if (['Medium Risk'].includes(data.status)) vBadge.style.color = 'var(--amber)';
  else vBadge.style.color = 'var(--red)';

  document.getElementById('rpt-score').textContent = (100 - (data.riskScore || 0)) + ' / 100';
  document.getElementById('rpt-conf').textContent = (data.confidenceScore || 95) + '%';

  // Network checks
  const d = data.details || {};
  document.getElementById('rpt-network').innerHTML = `
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

  // Headers
  const h = d.headerChecks || {};
  document.getElementById('rpt-headers').innerHTML = `
    <tr><td style="font-weight:600; width:30%;">Strict-Transport-Security</td><td class="${h.hsts ? 'text-cyan' : ''}">${h.hsts ? 'Present' : 'Missing'}</td></tr>
    <tr><td style="font-weight:600;">Content-Security-Policy</td><td class="${h.csp ? 'text-cyan' : ''}">${h.csp ? 'Present' : 'Missing'}</td></tr>
    <tr><td style="font-weight:600;">X-Frame-Options</td><td class="${h.xFrameOptions ? 'text-cyan' : ''}">${h.xFrameOptions ? 'Present' : 'Missing'}</td></tr>
    <tr><td style="font-weight:600;">X-Content-Type-Options</td><td class="${h.xContentTypeOptions ? 'text-cyan' : ''}">${h.xContentTypeOptions ? 'Present' : 'Missing'}</td></tr>
    <tr><td style="font-weight:600;">Referrer-Policy</td><td class="${h.referrerPolicy ? 'text-cyan' : ''}">${h.referrerPolicy ? 'Present' : 'Missing'}</td></tr>
  `;

  // Recommendations
  const recList = document.getElementById('rpt-recs');
  const recs = data.recommendations || [];
  
  if (recs.length === 0) {
    recList.innerHTML = `<li style="list-style:none; color:var(--green);"><i class="fas fa-check"></i> Target conforms to primary security benchmarks. No immediate action required.</li>`;
  } else {
    recList.innerHTML = recs.map(r => `<li style="margin-bottom:10px;">${escapeHtml(r)}</li>`).join('');
  }
}
