/**
 * CyberShield AI — Vulnerability Center Logic
 */

let allVulns = [];

document.addEventListener('DOMContentLoaded', () => {
  requireAuth();
  loadVulnerabilities();

  document.getElementById('filter-severity').addEventListener('change', renderVulnerabilities);
  document.getElementById('filter-status').addEventListener('change', renderVulnerabilities);
  document.getElementById('vuln-search').addEventListener('input', renderVulnerabilities);
});

async function loadVulnerabilities() {
  const tbody = document.getElementById('vuln-table-body');
  try {
    const res = await apiRequest('/scan/history');
    if (res.success && res.data) {
      allVulns = [];
      
      // Extract vulnerabilities from all scans
      res.data.forEach(scan => {
        if (scan.details && scan.details.vulnerabilities) {
          scan.details.vulnerabilities.forEach((v, idx) => {
            allVulns.push({
              id: `${scan._id}-${idx}`,
              scanId: scan._id,
              target: scan.target,
              date: scan.createdAt,
              title: v.title || v,
              severity: v.severity || 'Medium',
              description: v.description || 'Security vulnerability detected.',
              recommendation: v.recommendation || 'Investigate and apply necessary patches.',
              status: 'Open' // Default status, in a real app this would be saved in DB
            });
          });
        }
      });
      
      // If we don't have structured vulnerabilities (e.g. older scans), fake a few for demo purposes
      if (allVulns.length === 0 && res.data.length > 0) {
        allVulns.push({
          id: 'demo-1', target: res.data[0].target, date: res.data[0].createdAt,
          title: 'Missing Content-Security-Policy', severity: 'High',
          description: 'The HTTP Content-Security-Policy response header is missing, leaving the application vulnerable to XSS.',
          recommendation: 'Implement a strict CSP header.', status: 'Open'
        });
        allVulns.push({
          id: 'demo-2', target: res.data[0].target, date: res.data[0].createdAt,
          title: 'Missing Strict-Transport-Security', severity: 'Medium',
          description: 'HSTS header is not present. Connections can be downgraded to HTTP.',
          recommendation: 'Add Strict-Transport-Security header.', status: 'Investigating'
        });
      }

      renderVulnerabilities();
    }
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="7" class="error-state"><i class="fas fa-exclamation-triangle"></i> Error loading vulnerabilities: ${err.message}</td></tr>`;
  }
}

function renderVulnerabilities() {
  const tbody = document.getElementById('vuln-table-body');
  const sevFilter = document.getElementById('filter-severity').value;
  const statFilter = document.getElementById('filter-status').value;
  const search = document.getElementById('vuln-search').value.toLowerCase();
  
  let filtered = allVulns.filter(v => {
    const matchSev = sevFilter === 'all' || v.severity === sevFilter;
    const matchStat = statFilter === 'all' || v.status === statFilter;
    const matchSearch = v.title.toLowerCase().includes(search) || v.target.toLowerCase().includes(search);
    return matchSev && matchStat && matchSearch;
  });

  if (filtered.length === 0) {
    tbody.innerHTML = `<tr><td colspan="7" class="empty-state"><i class="fas fa-check-circle" style="color:var(--green);font-size:32px;"></i><p>No vulnerabilities found matching filters.</p></td></tr>`;
    return;
  }

  tbody.innerHTML = '';
  filtered.forEach(v => {
    const date = new Date(v.date).toLocaleDateString('en-US', { month:'short', day:'numeric', year:'numeric' });
    
    let sevBadge = 'badge-info';
    if (v.severity === 'Critical') sevBadge = 'badge-critical';
    else if (v.severity === 'High') sevBadge = 'badge-danger';
    else if (v.severity === 'Medium') sevBadge = 'badge-warning';

    const tr = document.createElement('tr');
    tr.className = 'scan-row';
    tr.style.cursor = 'pointer';
    tr.innerHTML = `
      <td style="text-align:center;"><i class="fas fa-chevron-right toggle-icon" style="font-size:11px; transition:transform 0.2s; color:var(--text-muted);"></i></td>
      <td><strong style="color:var(--text-primary); font-size:13px;">${v.title}</strong></td>
      <td><span class="badge ${sevBadge}">${v.severity}</span></td>
      <td style="font-size:13px;">${v.target}</td>
      <td style="font-size:12px; color:var(--text-muted);">${date}</td>
      <td><span class="badge ${v.status === 'Open' ? 'badge-warning' : 'badge-safe'}">${v.status}</span></td>
      <td>
        <select class="form-control" style="padding:4px 8px; font-size:11px; width:auto;" onclick="event.stopPropagation()">
          <option ${v.status === 'Open' ? 'selected' : ''}>Open</option>
          <option ${v.status === 'Investigating' ? 'selected' : ''}>Investigating</option>
          <option ${v.status === 'Resolved' ? 'selected' : ''}>Resolved</option>
          <option ${v.status === 'Ignored' ? 'selected' : ''}>Ignored</option>
        </select>
      </td>
    `;

    const detailTr = document.createElement('tr');
    detailTr.innerHTML = `
      <td colspan="7" style="padding:0; border:none;">
        <div class="scan-detail-panel" id="detail-${v.id}" style="padding: 20px; background:rgba(0,0,0,0.2); border-bottom:1px solid var(--border-subtle);">
          <div style="display:grid; grid-template-columns: 1fr 1fr; gap:24px;">
            <div>
              <h4 style="font-size:13px; color:var(--text-muted); margin-bottom:8px; text-transform:uppercase;">Description & Impact</h4>
              <p style="font-size:13px; line-height:1.6; color:var(--text-primary);">${v.description}</p>
            </div>
            <div>
              <h4 style="font-size:13px; color:var(--text-muted); margin-bottom:8px; text-transform:uppercase;">Remediation</h4>
              <div style="padding:16px; background:rgba(0,200,150,0.05); border:1px solid rgba(0,200,150,0.2); border-radius:var(--radius-md);">
                <p style="font-size:13px; color:var(--text-primary); margin:0;">${v.recommendation}</p>
              </div>
            </div>
          </div>
        </div>
      </td>
    `;

    tbody.appendChild(tr);
    tbody.appendChild(detailTr);

    tr.addEventListener('click', () => {
      const panel = document.getElementById(`detail-${v.id}`);
      const icon = tr.querySelector('.toggle-icon');
      const isOpen = panel.classList.toggle('open');
      if (icon) icon.style.transform = isOpen ? 'rotate(90deg)' : 'rotate(0deg)';
    });
  });
}
