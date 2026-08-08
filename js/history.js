/**
 * CyberShield AI — History Logic
 */

document.addEventListener('DOMContentLoaded', async () => {
  const tableBody = document.getElementById('history-table-body');
  const searchInput = document.getElementById('history-search');
  const filterSelect = document.getElementById('history-filter');
  
  let allData = [];
  
  async function loadHistory() {
    try {
      const res = await apiRequest('/scan/history');
      if (res.success && res.data) {
        allData = res.data;
        renderTable(allData);
      }
    } catch (e) {
      tableBody.innerHTML = '<tr><td colspan="6" style="text-align:center; color:var(--neon-red);">Failed to load history</td></tr>';
    }
  }

  function renderTable(data) {
    if (!data || data.length === 0) {
      tableBody.innerHTML = '<tr><td colspan="6" style="text-align:center; color:var(--text-muted);">No scan history found</td></tr>';
      return;
    }
    
    tableBody.innerHTML = data.map(item => {
      const time = new Date(item.createdAt).toLocaleString();
      const isThreat = ['Phishing','High Risk','Critical'].includes(item.status);
      const badgeClass = isThreat ? 'badge-danger' : item.status === 'Safe' ? 'badge-safe' : 'badge-warning';
      
      const typeMap = {
        'url_phishing': 'URL Phishing',
        'website_security': 'Website Audit',
        'ip_reputation': 'IP Check',
        'file_hash': 'File Scan',
        'password_check': 'Password'
      };
      
      return `
        <tr>
          <td><strong style="color:#fff;">${item.target.substring(0, 40)}${item.target.length > 40 ? '...' : ''}</strong></td>
          <td><span style="color:var(--text-muted); font-size:13px;">${typeMap[item.scanType] || item.scanType}</span></td>
          <td><span class="badge ${badgeClass}">${item.status}</span></td>
          <td><span style="color:${isThreat ? 'var(--neon-red)' : 'var(--neon-green)'}; font-weight:600;">${item.riskScore}% Risk</span></td>
          <td style="color:var(--text-muted); font-size:13px;">${time}</td>
          <td><button class="btn btn-secondary" style="padding:4px 10px; font-size:12px;" onclick="viewReport('${item._id}')"><i class="fas fa-eye"></i> View</button></td>
        </tr>
      `;
    }).join('');
  }

  function filterData() {
    const search = searchInput.value.toLowerCase();
    const filter = filterSelect.value;
    
    const filtered = allData.filter(item => {
      const matchSearch = item.target.toLowerCase().includes(search);
      const matchFilter = filter === 'all' || item.status === filter;
      return matchSearch && matchFilter;
    });
    
    renderTable(filtered);
  }

  searchInput.addEventListener('input', filterData);
  filterSelect.addEventListener('change', filterData);
  
  window.viewReport = (id) => {
    // Basic stub for view functionality
    showToast('Report generation feature coming soon for id: ' + id, 'info');
  };

  await loadHistory();
});
