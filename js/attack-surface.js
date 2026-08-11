/**
 * CyberShield - Attack Surface Map Logic
 * Uses vis-network to visualize assets
 */

document.addEventListener('DOMContentLoaded', () => {
  requireAuth();
  
  const generateBtn = document.getElementById('btn-map-generate');
  const targetInput = document.getElementById('map-target-input');

  generateBtn.addEventListener('click', async () => {
    const target = targetInput.value.trim();
    if (!target) return showToast('Enter a target domain', 'warning');
    
    generateBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Mapping...';
    generateBtn.disabled = true;

    try {
      const res = await apiRequest('/scan/website', 'POST', { url: target });
      
      if (res.success && res.data) {
        drawMap(target, res.data);
        showToast('Attack surface mapped successfully', 'success');
      } else {
        throw new Error(res.error || 'Failed to scan');
      }
    } catch(err) {
      showToast('Using demo map: ' + err.message, 'warning');
      drawDemoMap(target);
    } finally {
      generateBtn.innerHTML = '<i class="fas fa-project-diagram"></i> Generate Map';
      generateBtn.disabled = false;
    }
  });

  drawDemoMap('cybershield.io');

  const exportBtn = document.getElementById('btn-export-map-pdf');
  if (exportBtn) {
    exportBtn.addEventListener('click', (e) => {
      e.preventDefault();
      const targetInput = document.getElementById('map-target-input');
      const target = (targetInput && targetInput.value.trim()) || 'cybershield.io';
      downloadReportPDF({ type: 'attack_surface', target, scanType: 'website_security' }, 'CyberShield_Attack_Surface_Report.pdf');
    });
  }
});

function drawMap(domain, scanData) {
  const container = document.getElementById('network-map');
  
  const nodes = new vis.DataSet([
    { id: 1, label: domain, shape: 'box', color: { background: '#0d1b2a', border: '#00d4ff' }, font: { color: '#fff', size: 16, face: 'Inter', bold: true }, borderWidth: 3 }
  ]);
  const edges = new vis.DataSet([]);
  let nodeId = 2;

  // SSL Node
  const sslOk = scanData.hasHttps;
  const sslColor = sslOk ? '#00c896' : '#ef4444';
  nodes.add({ id: nodeId, label: sslOk ? '🔒 SSL: Valid' : '⚠️ SSL: Missing', shape: 'box', color: { background: '#0d1b2a', border: sslColor }, font: { color: '#fff' }, borderWidth: 2 });
  edges.add({ from: 1, to: nodeId, color: { color: sslColor }, width: 2 });
  nodeId++;

  // Headers Node
  const hdrOk = scanData.headerChecks && scanData.headerChecks.hsts && scanData.headerChecks.csp;
  const hdrColor = hdrOk ? '#00c896' : '#f59e0b';
  nodes.add({ id: nodeId, label: hdrOk ? '🛡️ Headers: Strong' : '⚠️ Headers: Weak', shape: 'box', color: { background: '#0d1b2a', border: hdrColor }, font: { color: '#fff' }, borderWidth: 2 });
  edges.add({ from: 1, to: nodeId, color: { color: hdrColor }, width: 2 });
  const headersNodeId = nodeId;
  nodeId++;

  // IP/DNS Node
  const ip = scanData.resolvedIp || 'Unknown IP';
  nodes.add({ id: nodeId, label: '🌐 ' + ip, shape: 'box', color: { background: '#0d1b2a', border: '#8b5cf6' }, font: { color: '#fff' }, borderWidth: 2 });
  edges.add({ from: 1, to: nodeId, color: { color: '#8b5cf6' }, width: 2 });
  nodeId++;

  // Subdomains
  ['api', 'mail', 'dev'].forEach(s => {
    nodes.add({ id: nodeId, label: s + '.' + domain, shape: 'ellipse', color: { background: 'rgba(0,212,255,0.1)', border: '#00d4ff' }, font: { color: '#ccc', size: 12 } });
    edges.add({ from: 1, to: nodeId, color: { color: 'rgba(0,212,255,0.2)' }, dashes: true });
    nodeId++;
  });

  // Vulnerabilities
  if (scanData.vulnerabilities && scanData.vulnerabilities.length > 0) {
    scanData.vulnerabilities.forEach(v => {
      const vColor = v.severity === 'Critical' || v.severity === 'High' ? '#ef4444' : '#f59e0b';
      nodes.add({ id: nodeId, label: '⚠ ' + v.title, shape: 'box', color: { background: 'rgba(239,68,68,0.08)', border: vColor }, font: { color: '#fff', size: 11 }, borderWidth: 1 });
      edges.add({ from: headersNodeId, to: nodeId, color: { color: vColor }, dashes: true });
      nodeId++;
    });
  }

  // Missing headers
  if (scanData.missingHeaders && scanData.missingHeaders.length > 0) {
    scanData.missingHeaders.forEach(h => {
      nodes.add({ id: nodeId, label: '❌ ' + h, shape: 'box', color: { background: 'rgba(245,158,11,0.08)', border: '#f59e0b' }, font: { color: '#ddd', size: 11 } });
      edges.add({ from: headersNodeId, to: nodeId, color: { color: '#f59e0b' }, dashes: true });
      nodeId++;
    });
  }

  renderVisNetwork(container, nodes, edges);
}

function drawDemoMap(domain) {
  const container = document.getElementById('network-map');
  const nodes = new vis.DataSet([
    { id: 1, label: domain, shape: 'box', color: { background: '#0d1b2a', border: '#00d4ff' }, font: { color: '#fff', size: 16, bold: true }, borderWidth: 3 },
    { id: 2, label: '🔒 SSL: Valid', shape: 'box', color: { background: '#0d1b2a', border: '#00c896' }, font: { color: '#fff' }, borderWidth: 2 },
    { id: 3, label: '⚠️ Headers: Weak', shape: 'box', color: { background: '#0d1b2a', border: '#f59e0b' }, font: { color: '#fff' }, borderWidth: 2 },
    { id: 4, label: '⚠ Missing CSP', shape: 'box', color: { background: 'rgba(245,158,11,0.08)', border: '#f59e0b' }, font: { color: '#ddd', size: 11 } },
    { id: 5, label: '🌐 10.0.0.45', shape: 'box', color: { background: '#0d1b2a', border: '#8b5cf6' }, font: { color: '#fff' }, borderWidth: 2 },
    { id: 6, label: 'api.' + domain, shape: 'ellipse', color: { background: 'rgba(0,212,255,0.1)', border: '#00d4ff' }, font: { color: '#ccc', size: 12 } },
    { id: 7, label: 'dev.' + domain, shape: 'ellipse', color: { background: 'rgba(0,212,255,0.1)', border: '#00d4ff' }, font: { color: '#ccc', size: 12 } },
    { id: 8, label: '⚠ Exposed Admin', shape: 'box', color: { background: 'rgba(239,68,68,0.08)', border: '#ef4444' }, font: { color: '#fff', size: 11 } },
  ]);

  const edges = new vis.DataSet([
    { from: 1, to: 2, color: { color: '#00c896' }, width: 2 },
    { from: 1, to: 3, color: { color: '#f59e0b' }, width: 2 },
    { from: 1, to: 5, color: { color: '#8b5cf6' }, width: 2 },
    { from: 1, to: 6, color: { color: 'rgba(0,212,255,0.2)' }, dashes: true },
    { from: 1, to: 7, color: { color: 'rgba(0,212,255,0.2)' }, dashes: true },
    { from: 7, to: 8, color: { color: '#ef4444' }, dashes: true },
    { from: 3, to: 4, color: { color: '#f59e0b' }, dashes: true }
  ]);

  renderVisNetwork(container, nodes, edges);
}

function renderVisNetwork(container, nodes, edges) {
  const VisLib = (typeof vis !== 'undefined' ? vis : (typeof window !== 'undefined' ? window.vis : null));
  if (!VisLib || !VisLib.Network) {
    console.error('[vis.js Error] vis-network library is not available');
    if (typeof showToast === 'function') showToast('Network visualizer initializing...', 'info');
    return;
  }
  const data = { nodes, edges };
  const options = {
    nodes: { font: { face: 'Inter', size: 13 }, margin: 10 },
    edges: { width: 2, smooth: { type: 'continuous' } },
    physics: {
      barnesHut: { gravitationalConstant: -3000, centralGravity: 0.3, springLength: 160 }
    },
    interaction: { hover: true, tooltipDelay: 200 }
  };
  new VisLib.Network(container, data, options);
}
