/**
 * CyberShield - Security Investigation Mode Logic
 */

document.addEventListener('DOMContentLoaded', () => {
  requireAuth();

  const scanStr = localStorage.getItem('lastScanData');
  if (!scanStr) {
    showToast('No investigation data found. Redirecting...', 'warning');
    setTimeout(() => { window.location.href = 'scanner.html'; }, 2000);
    return;
  }

  let scanData;
  try {
    scanData = JSON.parse(scanStr);
  } catch (e) {
    showToast('Invalid data format', 'danger');
    return;
  }

  renderInvestigation(scanData);
});

function renderInvestigation(data) {
  const details = data.details || data;
  const target = data.target || data.url || details.domain || 'Unknown Target';
  const status = data.status || data.riskLevel || details.riskLevel || 'Unknown';
  const riskScore = data.riskScore != null ? data.riskScore : (details.securityScore != null ? (100 - details.securityScore) : 0);
  const secScore = details.securityScore != null ? details.securityScore : (100 - (riskScore || 0));

  // Populate Meta
  document.getElementById('inv-target').textContent = target;
  document.getElementById('inv-date').textContent = new Date().toLocaleString();
  document.getElementById('inv-score').textContent = secScore + '/100';
  document.getElementById('inv-ip').textContent = details.resolvedIp || 'N/A';
  document.getElementById('inv-proto').textContent = details.hasHttps ? 'HTTPS (Secure)' : 'HTTP (Insecure)';
  document.getElementById('inv-conf').textContent = (data.confidenceScore || details.confidenceScore || 95) + '%';
  
  const badge = document.getElementById('inv-badge');
  badge.textContent = status;
  if (['Safe','Clean','Low Risk'].includes(status)) badge.className = 'badge badge-safe';
  else if (['Medium Risk'].includes(status)) badge.className = 'badge badge-warning';
  else badge.className = 'badge badge-critical';

  // Populate Timelines (mocked based on current time for effect)
  const now = Date.now();
  document.getElementById('time-1').textContent = new Date(now - 120000).toLocaleTimeString();
  document.getElementById('time-2').textContent = new Date(now - 90000).toLocaleTimeString();
  document.getElementById('time-3').textContent = new Date(now - 45000).toLocaleTimeString();
  document.getElementById('time-4').textContent = new Date(now).toLocaleTimeString();

  // Populate Findings
  const findingsList = document.getElementById('inv-findings');
  let findingsHtml = '';
  
  if (!details.hasHttps) {
    findingsHtml += `<li><span class="text-red"><i class="fas fa-lock-open"></i> No SSL/TLS encryption</span> <span class="badge badge-critical">Critical</span></li>`;
  } else {
    findingsHtml += `<li><span class="text-green"><i class="fas fa-lock"></i> Valid SSL/TLS</span> <span class="badge badge-safe">Pass</span></li>`;
  }

  const h = details.headerChecks || {};
  let missingHeadersCount = 0;
  if (!h.hsts) missingHeadersCount++;
  if (!h.csp) missingHeadersCount++;
  if (!h.xFrameOptions) missingHeadersCount++;

  if (missingHeadersCount > 0) {
    findingsHtml += `<li><span class="text-amber"><i class="fas fa-shield-halved"></i> ${missingHeadersCount} Missing Security Headers</span> <span class="badge badge-warning">Medium</span></li>`;
  }

  const vulns = details.vulnerabilities || [];
  if (vulns.length > 0) {
    findingsHtml += `<li><span class="text-red"><i class="fas fa-bug"></i> ${vulns.length} Vulnerabilities Detected</span> <span class="badge badge-critical">High</span></li>`;
  }

  if (details.suspiciousPatterns) {
    findingsHtml += `<li><span class="text-red"><i class="fas fa-search-location"></i> Suspicious URL Patterns</span> <span class="badge badge-critical">High</span></li>`;
  }

  findingsList.innerHTML = findingsHtml || `<li><span class="text-green"><i class="fas fa-check"></i> No significant risks found</span></li>`;

  // Populate Recommendations
  const recList = document.getElementById('inv-recs');
  const recs = data.recommendations || details.recommendations || [];
  if (recs.length === 0) {
    recList.innerHTML = `<li><span class="text-green">No immediate action required. Monitor standard alerts.</span></li>`;
  } else {
    recList.innerHTML = recs.map(r => `<li style="margin-bottom:8px;">${escapeHtml(r)}</li>`).join('');
  }

  // Draw Graph
  drawInvestigationGraph(target, details, status, secScore);

  // Generate AI Summary
  generateAiSummary(target, details, status, secScore, vulns, missingHeadersCount);
}

function drawInvestigationGraph(domain, details, status, secScore) {
  const container = document.getElementById('investigation-graph');
  
  const nodes = new vis.DataSet([]);
  const edges = new vis.DataSet([]);
  
  let nodeId = 1;
  const rootId = nodeId++;
  
  // 1. Domain
  nodes.add({ id: rootId, label: '🌐 Target:\n' + domain, shape: 'box', color: { background: '#0d1b2a', border: '#00d4ff' }, font: { color: '#fff', face: 'Inter' }, borderWidth: 2 });

  // 2. DNS
  const dnsId = nodeId++;
  nodes.add({ id: dnsId, label: '📡 DNS: ' + (details.resolvedIp || 'Unknown'), shape: 'box', color: { background: '#0d1b2a', border: '#8b5cf6' }, font: { color: '#fff', face: 'Inter' }, borderWidth: 1 });
  edges.add({ from: rootId, to: dnsId, color: { color: '#8b5cf6' } });

  // 3. SSL
  const sslId = nodeId++;
  const sslColor = details.hasHttps ? '#00c896' : '#ef4444';
  nodes.add({ id: sslId, label: details.hasHttps ? '🔒 SSL: Valid' : '🔓 SSL: Missing', shape: 'box', color: { background: '#0d1b2a', border: sslColor }, font: { color: '#fff', face: 'Inter' }, borderWidth: 1 });
  edges.add({ from: rootId, to: sslId, color: { color: sslColor } });

  // 4. Headers
  const hdrId = nodeId++;
  const h = details.headerChecks || {};
  const hdrOk = h.hsts && h.csp;
  const hdrColor = hdrOk ? '#00c896' : '#f59e0b';
  nodes.add({ id: hdrId, label: hdrOk ? '🛡️ Headers: Strong' : '⚠️ Headers: Weak', shape: 'box', color: { background: '#0d1b2a', border: hdrColor }, font: { color: '#fff', face: 'Inter' }, borderWidth: 1 });
  edges.add({ from: rootId, to: hdrId, color: { color: hdrColor } });

  // 5. Threat Intel / AI Analysis
  const aiId = nodeId++;
  const isThreat = ['Phishing', 'Critical', 'High Risk'].includes(status);
  const aiColor = isThreat ? '#ef4444' : '#00d4ff';
  nodes.add({ id: aiId, label: '🧠 AI Analysis:\n' + status, shape: 'box', color: { background: isThreat ? 'rgba(239,68,68,0.1)' : 'rgba(0,212,255,0.1)', border: aiColor }, font: { color: '#fff', face: 'Inter' }, borderWidth: 2 });
  
  edges.add({ from: dnsId, to: aiId, color: { color: '#333' }, dashes: true });
  edges.add({ from: sslId, to: aiId, color: { color: '#333' }, dashes: true });
  edges.add({ from: hdrId, to: aiId, color: { color: '#333' }, dashes: true });

  // 6. Final Risk Score
  const scoreId = nodeId++;
  const scoreColor = secScore >= 90 ? '#00c896' : secScore >= 70 ? '#00d4ff' : secScore >= 50 ? '#f59e0b' : '#ef4444';
  nodes.add({ id: scoreId, label: '📊 Risk Score:\n' + secScore + '/100', shape: 'circle', color: { background: scoreColor, border: '#fff' }, font: { color: '#fff', face: 'Inter', bold: true }, borderWidth: 3 });
  edges.add({ from: aiId, to: scoreId, color: { color: scoreColor }, width: 3 });

  // Add specific vulnerabilities branching from Headers or AI
  if (details.vulnerabilities) {
    details.vulnerabilities.forEach(v => {
      const vId = nodeId++;
      nodes.add({ id: vId, label: '🚨 ' + v.title, shape: 'box', color: { background: 'rgba(239,68,68,0.1)', border: '#ef4444' }, font: { color: '#fff', size: 10 } });
      edges.add({ from: hdrId, to: vId, color: { color: '#ef4444' }, dashes: true });
    });
  }

  const data = { nodes, edges };
  const options = {
    layout: {
      hierarchical: {
        direction: 'LR',
        sortMethod: 'directed',
        levelSeparation: 150,
        nodeSpacing: 100
      }
    },
    physics: false,
    interaction: { dragNodes: true, zoomView: true, dragView: true }
  };
  
  new vis.Network(container, data, options);
}

function generateAiSummary(domain, details, status, secScore, vulns, missingHeadersCount) {
  const summaryBox = document.getElementById('ai-summary');
  let summary = `<strong>CyberShield AI Engine Analysis:</strong><br><br>`;
  
  if (['Safe', 'Clean', 'Low Risk'].includes(status)) {
    summary += `The target domain (<strong>${escapeHtml(domain)}</strong>) exhibits a strong security posture with a score of ${secScore}/100. `;
    if (details.hasHttps) summary += `Traffic is properly encrypted via SSL/TLS. `;
    if (missingHeadersCount === 0) summary += `All critical security headers are enforced. `;
    summary += `No immediate threats or phishing indicators were detected by the heuristic engine.`;
  } else {
    summary += `The target domain (<strong>${escapeHtml(domain)}</strong>) has been flagged as <strong>${escapeHtml(status)}</strong> with a depressed security score of ${secScore}/100. This indicates significant risk to users and systems interacting with this endpoint.<br><br>`;
    
    summary += `<strong>Key Risk Factors:</strong><ul>`;
    if (!details.hasHttps) {
      summary += `<li><strong>Missing SSL/TLS:</strong> The connection is unencrypted, exposing all transmitted data to Man-in-the-Middle (MitM) attacks.</li>`;
    }
    if (missingHeadersCount > 0) {
      summary += `<li><strong>Weak Security Headers:</strong> ${missingHeadersCount} critical headers (such as HSTS or CSP) are missing, leaving the site vulnerable to XSS and protocol downgrade attacks.</li>`;
    }
    if (vulns.length > 0) {
      summary += `<li><strong>Detected Vulnerabilities:</strong> Found ${vulns.length} specific CVEs or misconfigurations that could be actively exploited.</li>`;
    }
    if (details.suspiciousPatterns) {
      summary += `<li><strong>Phishing Indicators:</strong> The URL structure strongly resembles known credential-harvesting attacks.</li>`;
    }
    summary += `</ul>`;
    
    summary += `<strong>Conclusion:</strong> Interaction with this domain should be strictly blocked or heavily monitored. See the recommended actions below for remediation steps.`;
  }

  summaryBox.innerHTML = summary;
}
