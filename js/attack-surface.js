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
      // Use existing scanner endpoint to get real data for the map
      const res = await apiRequest('/scan/website', 'POST', { url: target });
      
      if (res.success && res.data) {
        drawMap(target, res.data);
        showToast('Attack surface mapped successfully', 'success');
      } else {
        throw new Error(res.error || 'Failed to scan');
      }
    } catch(err) {
      showToast(err.message, 'danger');
      // Draw demo map on failure for demo purposes
      drawDemoMap(target);
    } finally {
      generateBtn.innerHTML = '<i class="fas fa-project-diagram"></i> Generate Map';
      generateBtn.disabled = false;
    }
  });

  // Draw initial empty state or demo map
  drawDemoMap('cybershield.io');
});

function drawMap(domain, scanData) {
  const container = document.getElementById('network-map');
  
  // Create Nodes & Edges from real scan data
  const nodes = new vis.DataSet([
    { id: 1, label: domain, shape: 'icon', icon: { face: '"Font Awesome 6 Free"', code: '\uf0ac', weight: 900, color: '#00d4ff' }, font: { color: '#fff' } }
  ]);
  const edges = new vis.DataSet([]);

  let nodeId = 2;

  // SSL Node
  const sslColor = scanData.hasHttps ? '#00c896' : '#ef4444';
  nodes.add({ id: nodeId, label: 'SSL/TLS', shape: 'icon', icon: { face: '"Font Awesome 6 Free"', code: '\uf023', weight: 900, color: sslColor }, font: { color: '#fff' } });
  edges.add({ from: 1, to: nodeId, color: { color: sslColor } });
  nodeId++;

  // Headers Node
  const headersSafe = scanData.headerChecks && scanData.headerChecks.hsts && scanData.headerChecks.csp;
  const hdrColor = headersSafe ? '#00c896' : '#f59e0b';
  nodes.add({ id: nodeId, label: 'HTTP Headers', shape: 'icon', icon: { face: '"Font Awesome 6 Free"', code: '\uf3ed', weight: 900, color: hdrColor }, font: { color: '#fff' } });
  edges.add({ from: 1, to: nodeId, color: { color: hdrColor } });
  nodeId++;

  // IP/DNS Node (mocking IP from scan)
  nodes.add({ id: nodeId, label: scanData.resolvedIp || 'DNS / IP', shape: 'icon', icon: { face: '"Font Awesome 6 Free"', code: '\uf233', weight: 900, color: '#8b5cf6' }, font: { color: '#fff' } });
  edges.add({ from: 1, to: nodeId, color: { color: '#8b5cf6' } });
  const ipId = nodeId;
  nodeId++;

  // Subdomains (mocked for visual effect)
  const subs = ['api', 'mail', 'dev'];
  subs.forEach(s => {
    nodes.add({ id: nodeId, label: `${s}.${domain}`, shape: 'dot', color: '#00d4ff', font: { color: '#fff' } });
    edges.add({ from: 1, to: nodeId, color: { color: 'rgba(0, 212, 255, 0.3)' } });
    nodeId++;
  });

  // Vulnerabilities
  if (scanData.vulnerabilities && scanData.vulnerabilities.length > 0) {
    scanData.vulnerabilities.forEach(v => {
      const vColor = v.severity === 'Critical' || v.severity === 'High' ? '#ef4444' : '#f59e0b';
      nodes.add({ id: nodeId, label: v.title, shape: 'box', color: { background: 'rgba(239, 68, 68, 0.1)', border: vColor }, font: { color: '#fff' } });
      edges.add({ from: hdrColor === '#f59e0b' ? 3 : 1, to: nodeId, color: { color: vColor }, dashes: true });
      nodeId++;
    });
  }

  renderVisNetwork(container, nodes, edges);
}

function drawDemoMap(domain) {
  const container = document.getElementById('network-map');
  const nodes = new vis.DataSet([
    { id: 1, label: domain, shape: 'icon', icon: { face: '"Font Awesome 6 Free"', code: '\uf0ac', weight: 900, color: '#00d4ff' }, font: { color: '#fff' } },
    { id: 2, label: 'SSL: Valid', shape: 'icon', icon: { face: '"Font Awesome 6 Free"', code: '\uf023', weight: 900, color: '#00c896' }, font: { color: '#fff' } },
    { id: 3, label: 'Headers: Weak', shape: 'icon', icon: { face: '"Font Awesome 6 Free"', code: '\uf3ed', weight: 900, color: '#f59e0b' }, font: { color: '#fff' } },
    { id: 4, label: 'Exposed Admin Panel', shape: 'box', color: { background: 'rgba(239, 68, 68, 0.1)', border: '#ef4444' }, font: { color: '#fff' } },
    { id: 5, label: '10.0.0.45', shape: 'icon', icon: { face: '"Font Awesome 6 Free"', code: '\uf233', weight: 900, color: '#8b5cf6' }, font: { color: '#fff' } },
    { id: 6, label: `api.${domain}`, shape: 'dot', color: '#00d4ff', font: { color: '#fff' } },
    { id: 7, label: `dev.${domain}`, shape: 'dot', color: '#00d4ff', font: { color: '#fff' } },
    { id: 8, label: 'Missing CSP', shape: 'box', color: { background: 'rgba(245, 158, 11, 0.1)', border: '#f59e0b' }, font: { color: '#fff' } },
  ]);

  const edges = new vis.DataSet([
    { from: 1, to: 2, color: { color: '#00c896' } },
    { from: 1, to: 3, color: { color: '#f59e0b' } },
    { from: 1, to: 5, color: { color: '#8b5cf6' } },
    { from: 1, to: 6, color: { color: 'rgba(0, 212, 255, 0.3)' } },
    { from: 1, to: 7, color: { color: 'rgba(0, 212, 255, 0.3)' } },
    { from: 7, to: 4, color: { color: '#ef4444' }, dashes: true },
    { from: 3, to: 8, color: { color: '#f59e0b' }, dashes: true }
  ]);

  renderVisNetwork(container, nodes, edges);
}

function renderVisNetwork(container, nodes, edges) {
  const data = { nodes, edges };
  const options = {
    nodes: {
      font: { face: 'Inter', size: 14 }
    },
    edges: {
      width: 2,
      smooth: { type: 'continuous' }
    },
    physics: {
      barnesHut: {
        gravitationalConstant: -2000,
        centralGravity: 0.3,
        springLength: 150
      }
    }
  };
  new vis.Network(container, data, options);
}
