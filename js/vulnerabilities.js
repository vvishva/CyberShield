/**
 * CyberShield AI — Vulnerability Center & Intelligence Logic
 */

let allVulns = [];
let selectedVuln = null;

document.addEventListener('DOMContentLoaded', () => {
  requireAuth();
  loadVulnerabilities();

  document.getElementById('filter-severity').addEventListener('change', renderVulnerabilities);
  document.getElementById('filter-status').addEventListener('change', renderVulnerabilities);
  document.getElementById('vuln-search').addEventListener('input', renderVulnerabilities);

  const exportBtn = document.getElementById('btn-export-vuln-pdf');
  if (exportBtn) {
    exportBtn.addEventListener('click', (e) => {
      e.preventDefault();
      downloadReportPDF({ type: 'vulnerabilities' }, 'CyberShield_Vulnerabilities_Report.pdf');
    });
  }

  const explainAllBtn = document.getElementById('btn-explain-all-ai');
  if (explainAllBtn) {
    explainAllBtn.addEventListener('click', handleExplainAllAI);
  }

  // Drawer handlers
  const closeDrawerBtn = document.getElementById('btn-close-vuln-drawer');
  const backdrop = document.getElementById('vuln-drawer-backdrop');
  if (closeDrawerBtn) closeDrawerBtn.addEventListener('click', closeVulnDrawer);
  if (backdrop) backdrop.addEventListener('click', closeVulnDrawer);

  const escalateBtn = document.getElementById('btn-escalate-from-vuln');
  if (escalateBtn) escalateBtn.addEventListener('click', handleEscalateToIncident);

  const resolveBtn = document.getElementById('btn-mark-vuln-resolved');
  if (resolveBtn) resolveBtn.addEventListener('click', handleMarkResolved);
});

async function loadVulnerabilities() {
  const tbody = document.getElementById('vuln-table-body');
  try {
    const res = await apiRequest('/scan/history');
    if (res.success && res.data) {
      allVulns = [];
      
      // Extract vulnerabilities from all scans
      res.data.forEach(scan => {
        if (scan.details && Array.isArray(scan.details.vulnerabilities)) {
          scan.details.vulnerabilities.forEach((v, idx) => {
            const title = v.title || v.name || v;
            const severity = (v.severity || 'Medium').toUpperCase();
            allVulns.push({
              id: `${scan._id}-${idx}`,
              scanId: scan._id,
              target: scan.target,
              date: scan.createdAt,
              title,
              severity: severity.charAt(0) + severity.slice(1).toLowerCase(),
              cve: v.cve || (title.includes('CSP') ? 'CWE-1021' : title.includes('HSTS') ? 'CWE-319' : title.includes('X-Frame') ? 'CWE-693' : 'CWE-200'),
              cvss: severity === 'CRITICAL' ? '9.1' : severity === 'HIGH' ? '7.5' : severity === 'MEDIUM' ? '5.3' : '3.1',
              description: v.description || 'Security vulnerability identified during surface inspection.',
              recommendation: v.recommendation || 'Apply perimeter header configurations or patch target web service.',
              status: 'Open'
            });
          });
        }
      });
      
      // Baseline fallback vulnerabilities if no structured scans yet
      if (allVulns.length === 0) {
        allVulns = [
          {
            id: 'vuln-base-1',
            target: 'api.production.internal',
            date: new Date(Date.now() - 3600000),
            title: 'Missing Content-Security-Policy',
            severity: 'High',
            cve: 'CWE-1021',
            cvss: '7.5',
            description: 'The HTTP Content-Security-Policy response header is missing, allowing unrestricted script execution.',
            recommendation: "Implement strict CSP: `Content-Security-Policy: default-src 'self'`",
            status: 'Open'
          },
          {
            id: 'vuln-base-2',
            target: 'auth.portal-login.xyz',
            date: new Date(Date.now() - 7200000),
            title: 'Homograph Domain Spoofing & Phishing Target',
            severity: 'Critical',
            cve: 'CWE-451',
            cvss: '9.4',
            description: 'Rogue impersonation hostname flagged harvesting authentication tokens.',
            recommendation: 'Initiate registrar takedown notice and block traffic on perimeter gateway.',
            status: 'Investigating'
          },
          {
            id: 'vuln-base-3',
            target: 'gateway.cloud-network.io',
            date: new Date(Date.now() - 14400000),
            title: 'Strict-Transport-Security (HSTS) Missing',
            severity: 'Medium',
            cve: 'CWE-319',
            cvss: '5.3',
            description: 'HTTP response header lacks HSTS max-age directive, leaving initial connections open to downgrade.',
            recommendation: 'Add header: `Strict-Transport-Security: max-age=31536000; includeSubDomains`',
            status: 'Open'
          },
          {
            id: 'vuln-base-4',
            target: 'CyberShield Auth Gateway',
            date: new Date(Date.now() - 86400000),
            title: 'Server Banner Information Disclosure',
            severity: 'Low',
            cve: 'CWE-200',
            cvss: '3.1',
            description: 'Server banner reveals exact web server software version in response headers.',
            recommendation: 'Disable Server header in Nginx via `server_tokens off;`',
            status: 'Resolved'
          }
        ];
      }

      updateVulnStats();
      renderVulnerabilities();
    }
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="8" class="error-state"><i class="fas fa-exclamation-triangle"></i> Error loading vulnerabilities: ${err.message}</td></tr>`;
  }
}

function updateVulnStats() {
  const set = (id, val) => {
    const el = document.getElementById(id);
    if (el) el.textContent = val || 0;
  };
  set('stat-crit-count', allVulns.filter(v => v.severity.toLowerCase() === 'critical').length);
  set('stat-high-count', allVulns.filter(v => v.severity.toLowerCase() === 'high').length);
  set('stat-med-count', allVulns.filter(v => v.severity.toLowerCase() === 'medium').length);
  set('stat-resolved-count', allVulns.filter(v => v.status === 'Resolved').length);
}

function renderVulnerabilities() {
  const tbody = document.getElementById('vuln-table-body');
  const sevFilter = document.getElementById('filter-severity').value;
  const statFilter = document.getElementById('filter-status').value;
  const search = document.getElementById('vuln-search').value.toLowerCase();
  
  let filtered = allVulns.filter(v => {
    const matchSev = sevFilter === 'all' || v.severity.toLowerCase() === sevFilter.toLowerCase();
    const matchStat = statFilter === 'all' || v.status === statFilter;
    const matchSearch = v.title.toLowerCase().includes(search) || v.target.toLowerCase().includes(search) || (v.cve && v.cve.toLowerCase().includes(search));
    return matchSev && matchStat && matchSearch;
  });

  if (filtered.length === 0) {
    tbody.innerHTML = `<tr><td colspan="8" class="empty-state"><i class="fas fa-check-circle" style="color:var(--green);font-size:32px;"></i><p>No vulnerabilities found matching filters.</p></td></tr>`;
    return;
  }

  tbody.innerHTML = '';
  filtered.forEach(v => {
    const date = new Date(v.date).toLocaleDateString('en-US', { month:'short', day:'numeric', year:'numeric' });
    
    let sevBadge = 'badge-info';
    if (v.severity.toLowerCase() === 'critical') sevBadge = 'badge-critical';
    else if (v.severity.toLowerCase() === 'high') sevBadge = 'badge-danger';
    else if (v.severity.toLowerCase() === 'medium') sevBadge = 'badge-warning';

    const statColor = v.status === 'Resolved' ? 'var(--green)' : v.status === 'Investigating' ? 'var(--amber)' : 'var(--cyan)';

    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td style="text-align:center;"><i class="fas fa-bug text-cyan"></i></td>
      <td>
        <strong style="color:var(--text-primary); font-size:13.5px;">${escapeHtml(v.title)}</strong>
        <div style="font-size:11.5px; color:var(--text-muted); margin-top:2px;">${escapeHtml(v.description.substring(0, 60))}...</div>
      </td>
      <td><span class="badge ${sevBadge}">${escapeHtml(v.severity)}</span></td>
      <td><code style="color:var(--cyan); font-size:12px;">${escapeHtml(v.target)}</code></td>
      <td><span style="font-family:var(--font-mono); font-size:12px; color:var(--text-muted);">${escapeHtml(v.cve || 'N/A')} (${v.cvss || '5.0'})</span></td>
      <td style="font-size:12px; color:var(--text-muted);">${date}</td>
      <td><span class="badge" style="color:${statColor}; border-color:${statColor}; font-size:11px;">${escapeHtml(v.status)}</span></td>
      <td style="text-align:right;">
        <button class="btn btn-secondary btn-sm btn-remediate" style="margin-right:6px;"><i class="fas fa-brain text-cyan"></i> Remediate</button>
      </td>
    `;

    tr.querySelector('.btn-remediate').addEventListener('click', () => openVulnDrawer(v));
    tbody.appendChild(tr);
  });
}

function openVulnDrawer(vuln) {
  selectedVuln = vuln;
  const drawer = document.getElementById('vuln-remediation-drawer');
  const backdrop = document.getElementById('vuln-drawer-backdrop');

  document.getElementById('drawer-vuln-title').textContent = vuln.title;
  document.getElementById('drawer-vuln-target').textContent = vuln.target;
  document.getElementById('drawer-vuln-desc').textContent = vuln.description;
  
  const sevEl = document.getElementById('drawer-vuln-sev');
  sevEl.textContent = vuln.severity;
  sevEl.className = `badge badge-${vuln.severity.toLowerCase() === 'critical' ? 'critical' : vuln.severity.toLowerCase() === 'high' ? 'danger' : 'warning'}`;

  const aiBox = document.getElementById('drawer-vuln-ai-plan');
  aiBox.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Generating tailored remediation blueprint with AI Sentinel...';

  if (drawer) drawer.classList.add('open');
  if (backdrop) backdrop.style.display = 'block';

  // Fetch AI explanation
  fetchVulnRemediationPlan(vuln);
}

function closeVulnDrawer() {
  const drawer = document.getElementById('vuln-remediation-drawer');
  const backdrop = document.getElementById('vuln-drawer-backdrop');
  if (drawer) drawer.classList.remove('open');
  if (backdrop) backdrop.style.display = 'none';
}

async function fetchVulnRemediationPlan(vuln) {
  const aiBox = document.getElementById('drawer-vuln-ai-plan');
  try {
    const res = await apiRequest('/ai/explain-vulnerability', 'POST', {
      vulnerabilityTitle: vuln.title,
      vulnerabilityDesc: vuln.description,
      severity: vuln.severity,
      target: vuln.target
    });

    if (res.success && res.data && res.data.explanation) {
      aiBox.innerHTML = window.formatMarkdownResponse ? window.formatMarkdownResponse(res.data.explanation) : `<p>${escapeHtml(res.data.explanation)}</p>`;
    } else {
      aiBox.innerHTML = `<p>${escapeHtml(vuln.recommendation)}</p>`;
    }
  } catch (err) {
    aiBox.innerHTML = `<p>${escapeHtml(vuln.recommendation)}</p>`;
  }
}

async function handleEscalateToIncident() {
  if (!selectedVuln) return;
  try {
    const res = await apiRequest('/incidents', 'POST', {
      title: `Remediation Incident: ${selectedVuln.title}`,
      severity: selectedVuln.severity.toUpperCase(),
      relatedAsset: selectedVuln.target,
      relatedVulnerability: selectedVuln.title,
      description: selectedVuln.description
    });

    if (res.success && res.data) {
      showToast('Incident created in Incident Response Hub.', 'success');
      closeVulnDrawer();
      setTimeout(() => {
        window.location.href = `investigation.html?incidentId=${encodeURIComponent(res.data.incidentId)}`;
      }, 1000);
    }
  } catch (err) {
    showToast(`Escalation failed: ${err.message}`, 'danger');
  }
}

function handleMarkResolved() {
  if (!selectedVuln) return;
  selectedVuln.status = 'Resolved';
  updateVulnStats();
  renderVulnerabilities();
  closeVulnDrawer();
  showToast(`Vulnerability marked as Resolved.`, 'success');
}

async function handleExplainAllAI() {
  showToast('Opening AI Copilot for environment vulnerability briefing...', 'info');
  const drawer = document.getElementById('ai-copilot-container');
  const fab = document.getElementById('ai-copilot-fab');
  if (drawer && fab) {
    drawer.classList.add('open');
    fab.classList.add('active');
  }
  const input = document.getElementById('ai-chat-input');
  if (input) {
    input.value = 'Summarize active vulnerabilities across my environment and prioritize fixes';
    const sendBtn = document.getElementById('ai-send-btn');
    if (sendBtn) sendBtn.click();
  }
}
