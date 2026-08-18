/**
 * CyberShield — Incident Response & Security Investigation Logic
 * Handles real-time incident lifecycle management, triage workflows, analyst notes, topology graphs, and AI remediation.
 */

let activeIncident = null;
let currentScanData = null;
let currentGraphNetwork = null;
let allIncidentsList = [];

document.addEventListener('DOMContentLoaded', async () => {
  requireAuth();

  // Bind Back Button
  const backBtn = document.getElementById('btn-back-inv');
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

  // Bind PDF Download Button
  const pdfBtn = document.getElementById('btn-generate-pdf');
  if (pdfBtn) {
    pdfBtn.addEventListener('click', (e) => {
      e.preventDefault();
      const targetName = activeIncident ? activeIncident.title : (currentScanData?.target || 'Incident_Report');
      downloadReportPDF({
        type: 'investigation',
        incidentId: activeIncident?.incidentId,
        scanId: currentScanData?._id
      }, `CyberShield_${activeIncident ? activeIncident.incidentId : 'Investigation'}.pdf`);
    });
  }

  // Bind AI Re-Analyze Button
  const reanalyzeBtn = document.getElementById('btn-reanalyze-ai');
  if (reanalyzeBtn) {
    reanalyzeBtn.addEventListener('click', handleAIReanalyze);
  }

  // Bind Add Note Form
  const noteForm = document.getElementById('add-note-form');
  if (noteForm) {
    noteForm.addEventListener('submit', handleAddNote);
  }

  // Bind Status Step Buttons
  const stepsContainer = document.getElementById('status-steps-container');
  if (stepsContainer) {
    stepsContainer.addEventListener('click', (e) => {
      const btn = e.target.closest('.status-step-pill');
      if (btn && btn.dataset.status) {
        handleStatusChange(btn.dataset.status);
      }
    });
  }

  // Bind Manual Create Incident Modal
  bindCreateIncidentModal();

  // Check URL parameters for incidentId or scanId
  const urlParams = new URLSearchParams(window.location.search);
  const incidentIdParam = urlParams.get('incidentId') || urlParams.get('id');
  const scanIdParam = urlParams.get('scanId');

  // Load Incidents Queue for Selector
  await loadIncidentsQueue(incidentIdParam);

  if (incidentIdParam) {
    await loadIncident(incidentIdParam);
  } else if (scanIdParam) {
    await loadScanData(scanIdParam);
  } else if (allIncidentsList.length > 0) {
    await loadIncident(allIncidentsList[0].incidentId);
  } else {
    // Fallback: Check local storage
    const scanStr = localStorage.getItem('lastScanData');
    if (scanStr) {
      try {
        const parsed = JSON.parse(scanStr);
        renderScanMode(parsed);
      } catch (e) {}
    }
  }

  // Bind Incident Selector Change
  const selector = document.getElementById('incident-selector');
  if (selector) {
    selector.addEventListener('change', (e) => {
      const val = e.target.value;
      if (val) loadIncident(val);
    });
  }

  // Bind Switch View Button
  const switchBtn = document.getElementById('btn-switch-scan-view');
  if (switchBtn) {
    switchBtn.addEventListener('click', () => {
      window.location.href = 'scanner.html';
    });
  }
});

// ── Load Incidents Queue ───────────────────────────────────────────────────
async function loadIncidentsQueue(selectId) {
  const selector = document.getElementById('incident-selector');
  try {
    const res = await apiRequest('/incidents');
    if (res.success && Array.isArray(res.data)) {
      allIncidentsList = res.data;
      if (selector) {
        selector.innerHTML = res.data.map(inc => `
          <option value="${escapeHtml(inc.incidentId)}" ${selectId === inc.incidentId ? 'selected' : ''}>
            [${inc.severity}] ${escapeHtml(inc.incidentId)} — ${escapeHtml(inc.title.substring(0, 35))}...
          </option>
        `).join('');
      }
    }
  } catch (err) {
    if (selector) selector.innerHTML = '<option value="">Default Sentinel Incident</option>';
  }
}

// ── Load Single Incident by ID ─────────────────────────────────────────────
async function loadIncident(id) {
  try {
    const res = await apiRequest(`/incidents/${id}`);
    if (res.success && res.data) {
      activeIncident = res.data;
      renderIncident(res.data);
    }
  } catch (err) {
    showToast(`Unable to load incident: ${err.message}`, 'danger');
  }
}

// ── Render Incident UI ─────────────────────────────────────────────────────
function renderIncident(incident) {
  // Update Header Elements
  const titleEl = document.getElementById('inv-title');
  if (titleEl) titleEl.textContent = incident.title;

  const idLabel = document.getElementById('inv-id-label');
  if (idLabel) idLabel.textContent = incident.incidentId;

  const sevBadge = document.getElementById('inv-severity-badge');
  if (sevBadge) {
    sevBadge.textContent = incident.severity;
    sevBadge.className = `badge badge-${incident.severity === 'CRITICAL' ? 'critical' : incident.severity === 'HIGH' ? 'danger' : incident.severity === 'MEDIUM' ? 'warning' : 'info'}`;
  }

  const statBadge = document.getElementById('inv-status-badge');
  if (statBadge) {
    statBadge.textContent = incident.status;
    statBadge.className = `badge badge-${incident.status === 'Resolved' || incident.status === 'Closed' ? 'safe' : incident.status === 'Contained' ? 'info' : 'warning'}`;
  }

  const assetEl = document.getElementById('inv-asset');
  if (assetEl) assetEl.textContent = incident.relatedAsset || 'Core Infrastructure';

  const analystEl = document.getElementById('inv-analyst');
  if (analystEl) analystEl.textContent = incident.assignedAnalyst || 'SOC Analyst';

  const timeEl = document.getElementById('inv-detection-time');
  if (timeEl) timeEl.textContent = new Date(incident.detectionTime || incident.createdAt).toLocaleString();

  // Score
  const scoreEl = document.getElementById('inv-score');
  if (scoreEl) {
    const score = incident.severity === 'CRITICAL' ? 25 : incident.severity === 'HIGH' ? 45 : incident.severity === 'MEDIUM' ? 68 : 88;
    scoreEl.textContent = `${score}/100`;
    scoreEl.style.color = score < 50 ? 'var(--red)' : score < 75 ? 'var(--amber)' : 'var(--green)';
  }

  // Update Status Step Bar
  updateStatusStepPills(incident.status);

  // Render AI Summary & Recommendations
  const aiBox = document.getElementById('ai-summary');
  if (aiBox) {
    if (incident.aiAnalysis) {
      aiBox.innerHTML = window.formatMarkdownResponse ? window.formatMarkdownResponse(incident.aiAnalysis) : `<p>${escapeHtml(incident.aiAnalysis)}</p>`;
      if (incident.recommendedResponse) {
        aiBox.innerHTML += `
          <div style="margin-top:14px; padding-top:10px; border-top:1px solid var(--border-subtle);">
            <strong style="color:var(--cyan);"><i class="fas fa-shield-check"></i> Recommended Containment Actions:</strong>
            <pre style="background:rgba(0,0,0,0.3); padding:10px; border-radius:4px; margin-top:6px; font-size:12px; white-space:pre-wrap; font-family:var(--font-mono);">${escapeHtml(incident.recommendedResponse)}</pre>
          </div>
        `;
      }
    } else {
      aiBox.innerHTML = `
        <p style="color:var(--text-muted);"><i class="fas fa-info-circle"></i> No AI analysis generated yet.</p>
        <button class="btn btn-primary btn-sm" onclick="handleAIReanalyze()"><i class="fas fa-brain"></i> Generate AI Root-Cause Analysis</button>
      `;
    }
  }

  // Render Evidence List
  const evidenceList = document.getElementById('inv-evidence-list');
  if (evidenceList) {
    const evidence = incident.evidence || [];
    if (evidence.length === 0) {
      evidenceList.innerHTML = '<li><span class="text-muted">No evidence artifacts attached</span></li>';
    } else {
      evidenceList.innerHTML = evidence.map(ev => `
        <li style="padding:10px 0; border-bottom:1px solid var(--border-subtle);">
          <div style="display:flex; justify-content:space-between; align-items:center;">
            <strong style="color:var(--cyan); font-size:12.5px;">${escapeHtml(ev.key || 'Artifact')}</strong>
            <span class="badge badge-info" style="font-size:11px;">${escapeHtml(ev.value || '')}</span>
          </div>
          ${ev.detail ? `<div style="font-size:11.5px; color:var(--text-muted); margin-top:4px;">${escapeHtml(ev.detail)}</div>` : ''}
        </li>
      `).join('');
    }
  }

  // Render Analyst Notes
  renderAnalystNotes(incident.investigationNotes);

  // Render Timeline
  renderTimeline(incident.timeline);

  // Render Topology Graph
  renderInvestigationGraph(incident);
}

// ── Status Progression Controls ────────────────────────────────────────────
function updateStatusStepPills(currentStatus) {
  const statuses = ['New', 'Investigating', 'Contained', 'Resolved', 'Closed'];
  const currentIndex = statuses.indexOf(currentStatus);

  document.querySelectorAll('.status-step-pill').forEach((pill, idx) => {
    pill.classList.remove('active', 'completed');
    if (idx < currentIndex) {
      pill.classList.add('completed');
      pill.innerHTML = `<i class="fas fa-check"></i> ${statuses[idx]}`;
    } else if (idx === currentIndex) {
      pill.classList.add('active');
      pill.innerHTML = `● ${statuses[idx]}`;
    } else {
      pill.innerHTML = `${idx + 1}. ${statuses[idx]}`;
    }
  });
}

async function handleStatusChange(newStatus) {
  if (!activeIncident) return;
  try {
    const res = await apiRequest(`/incidents/${activeIncident.incidentId}/status`, 'PATCH', {
      status: newStatus,
      note: `Analyst updated phase to ${newStatus}`
    });
    if (res.success && res.data) {
      activeIncident = res.data;
      renderIncident(res.data);
      showToast(`Incident status updated to ${newStatus}`, 'success');
      loadIncidentsQueue(activeIncident.incidentId);
    }
  } catch (err) {
    showToast(`Status update failed: ${err.message}`, 'danger');
  }
}

// ── Analyst Notes Handler ──────────────────────────────────────────────────
function renderAnalystNotes(notes) {
  const container = document.getElementById('analyst-notes-list');
  const countBadge = document.getElementById('notes-count-badge');
  if (!container) return;

  const list = notes || [];
  if (countBadge) countBadge.textContent = `${list.length} Notes`;

  if (list.length === 0) {
    container.innerHTML = `<div class="empty-state" style="padding:15px 0;"><p style="font-size:12px; margin:0;">No analyst notes logged yet.</p></div>`;
    return;
  }

  container.innerHTML = list.map(n => {
    const time = new Date(n.timestamp || Date.now()).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    return `
      <div class="analyst-note-card">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:4px;">
          <strong style="font-size:12px; color:var(--cyan);"><i class="fas fa-user-circle"></i> ${escapeHtml(n.author || 'Analyst')}</strong>
          <span style="font-size:10.5px; color:var(--text-muted); font-family:var(--font-mono);">${time}</span>
        </div>
        <div style="font-size:12.5px; color:var(--text-primary); line-height:1.4;">${escapeHtml(n.note)}</div>
      </div>
    `;
  }).join('');
}

async function handleAddNote(e) {
  e.preventDefault();
  const input = document.getElementById('analyst-note-input');
  if (!input || !input.value.trim() || !activeIncident) return;

  const noteText = input.value.trim();
  input.value = '';

  try {
    const res = await apiRequest(`/incidents/${activeIncident.incidentId}/notes`, 'POST', { note: noteText });
    if (res.success && res.data) {
      activeIncident = res.data;
      renderAnalystNotes(res.data.investigationNotes);
      renderTimeline(res.data.timeline);
      showToast('Investigation note saved.', 'success');
    }
  } catch (err) {
    showToast(`Failed to save note: ${err.message}`, 'danger');
  }
}

// ── AI Re-Analyze Handler ──────────────────────────────────────────────────
async function handleAIReanalyze() {
  if (!activeIncident) return;
  const aiBox = document.getElementById('ai-summary');
  const btn = document.getElementById('btn-reanalyze-ai');
  
  if (btn) btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Analyzing...';
  if (aiBox) aiBox.innerHTML = '<i class="fas fa-brain fa-spin"></i> Running Deep AI Sentinel Root-Cause Analysis...';

  try {
    const res = await apiRequest(`/incidents/${activeIncident.incidentId}/ai-analyze`, 'POST');
    if (res.success && res.data) {
      activeIncident.aiAnalysis = res.data.aiAnalysis;
      renderIncident(activeIncident);
      showToast('AI Incident Analysis complete.', 'success');
    }
  } catch (err) {
    if (aiBox) aiBox.innerHTML = `<p class="text-danger"><i class="fas fa-triangle-exclamation"></i> AI Analysis error: ${err.message}</p>`;
    showToast(`AI Analysis failed: ${err.message}`, 'danger');
  } finally {
    if (btn) btn.innerHTML = '<i class="fas fa-rotate"></i> AI Re-Analyze';
  }
}

// ── Render Timeline ────────────────────────────────────────────────────────
function renderTimeline(timeline) {
  const list = document.getElementById('inv-timeline-list');
  if (!list) return;

  const events = timeline || [];
  if (events.length === 0) {
    list.innerHTML = '<li><span class="text-muted">No timeline records</span></li>';
    return;
  }

  list.innerHTML = events.map(ev => {
    const time = new Date(ev.timestamp || Date.now()).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    return `
      <li style="padding:8px 0; border-bottom:1px solid var(--border-subtle);">
        <div style="display:flex; justify-content:space-between; align-items:center;">
          <strong style="font-size:12px; color:var(--text-primary);">${escapeHtml(ev.action)}</strong>
          <span style="font-size:10.5px; color:var(--text-muted); font-family:var(--font-mono);">${time}</span>
        </div>
        ${ev.detail ? `<div style="font-size:11.5px; color:var(--text-secondary); margin-top:2px;">${escapeHtml(ev.detail)}</div>` : ''}
      </li>
    `;
  }).join('');
}

// ── Interactive Threat & Asset Topology Graph ──────────────────────────────
function renderInvestigationGraph(data) {
  const container = document.getElementById('investigation-graph');
  if (!container || typeof vis === 'undefined') return;

  const target = data.relatedAsset || data.target || 'Target Asset';
  const nodes = [
    { id: 1, label: target, color: '#00d4ff', font: { color: '#ffffff', face: 'Inter' }, shape: 'diamond', size: 28 },
    { id: 2, label: data.relatedThreat || 'Threat Vector', color: '#ef4444', font: { color: '#ffffff', face: 'Inter' }, shape: 'dot', size: 20 },
    { id: 3, label: data.relatedVulnerability || 'Vulnerability', color: '#f59e0b', font: { color: '#ffffff', face: 'Inter' }, shape: 'dot', size: 18 },
    { id: 4, label: 'SSL / TLS Layer', color: '#00c896', font: { color: '#ffffff', face: 'Inter' }, shape: 'dot', size: 16 },
    { id: 5, label: 'HTTP Security Headers', color: '#8b5cf6', font: { color: '#ffffff', face: 'Inter' }, shape: 'dot', size: 16 }
  ];

  const edges = [
    { from: 1, to: 2, label: 'targeted by', color: { color: '#ef4444' }, arrows: 'to' },
    { from: 1, to: 3, label: 'exposed via', color: { color: '#f59e0b' } },
    { from: 1, to: 4, label: 'encrypted', color: { color: '#00c896' } },
    { from: 1, to: 5, label: 'defenses', color: { color: '#8b5cf6' } }
  ];

  const graphData = { nodes: new vis.DataSet(nodes), edges: new vis.DataSet(edges) };
  const options = {
    physics: { stabilization: true, barnesHut: { springLength: 120, springConstant: 0.04 } },
    interaction: { hover: true, zoomView: true }
  };

  if (currentGraphNetwork) currentGraphNetwork.destroy();
  currentGraphNetwork = new vis.Network(container, graphData, options);
}

// ── Create Incident Modal ──────────────────────────────────────────────────
function bindCreateIncidentModal() {
  const modal = document.getElementById('modal-create-incident');
  const backdrop = document.getElementById('modal-create-backdrop');
  const openBtn = document.getElementById('btn-create-manual-incident');
  const closeBtn = document.getElementById('btn-close-create-modal');
  const cancelBtn = document.getElementById('btn-cancel-create-modal');
  const form = document.getElementById('form-new-incident');

  const showModal = () => {
    if (modal) modal.style.display = 'block';
    if (backdrop) backdrop.style.display = 'block';
  };
  const hideModal = () => {
    if (modal) modal.style.display = 'none';
    if (backdrop) backdrop.style.display = 'none';
  };

  if (openBtn) openBtn.addEventListener('click', showModal);
  if (closeBtn) closeBtn.addEventListener('click', hideModal);
  if (cancelBtn) cancelBtn.addEventListener('click', hideModal);
  if (backdrop) backdrop.addEventListener('click', hideModal);

  if (form) {
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      const title = document.getElementById('modal-inc-title').value.trim();
      const severity = document.getElementById('modal-inc-severity').value;
      const asset = document.getElementById('modal-inc-asset').value.trim();
      const desc = document.getElementById('modal-inc-desc').value.trim();

      try {
        const res = await apiRequest('/incidents', 'POST', {
          title,
          severity,
          relatedAsset: asset || 'Web Application',
          description: desc
        });
        if (res.success && res.data) {
          hideModal();
          showToast('Security incident escalated successfully.', 'success');
          await loadIncidentsQueue(res.data.incidentId);
          await loadIncident(res.data.incidentId);
        }
      } catch (err) {
        showToast(`Failed to create incident: ${err.message}`, 'danger');
      }
    });
  }
}

// ── Scan Investigation Fallback / Mode ─────────────────────────────────────
async function loadScanData(scanId) {
  try {
    const res = await apiRequest('/scan/history');
    if (res.success && Array.isArray(res.data)) {
      const scan = res.data.find(s => s._id === scanId || s.id === scanId);
      if (scan) renderScanMode(scan);
    }
  } catch (e) {}
}

function renderScanMode(scan) {
  currentScanData = scan;
  const target = scan.target || 'Target Scan';
  const score = scan.details?.securityScore ?? (100 - (scan.riskScore || 0));

  const titleEl = document.getElementById('inv-title');
  if (titleEl) titleEl.textContent = `Security Scan Investigation: ${target}`;

  const scoreEl = document.getElementById('inv-score');
  if (scoreEl) scoreEl.textContent = `${score}/100`;

  const assetEl = document.getElementById('inv-asset');
  if (assetEl) assetEl.textContent = target;

  renderInvestigationGraph({ relatedAsset: target, relatedThreat: scan.status, relatedVulnerability: 'Header / SSL Checks' });
}
