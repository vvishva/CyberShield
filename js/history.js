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
      tableBody.innerHTML = '<tr><td colspan="6" style="text-align:center; color:var(--red);">Failed to load history</td></tr>';
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
          <td><strong style="color:#fff;">${escapeHtml((item.target || '').substring(0, 40))}${(item.target || '').length > 40 ? '...' : ''}</strong></td>
          <td><span style="color:var(--text-muted); font-size:13px;">${typeMap[item.scanType] || item.scanType}</span></td>
          <td><span class="badge ${badgeClass}">${escapeHtml(item.status)}</span></td>
          <td><span style="color:${isThreat ? 'var(--red)' : 'var(--green)'}; font-weight:600;">${item.riskScore}% Risk</span></td>
          <td style="color:var(--text-muted); font-size:13px;">${time}</td>
          <td>
            <div style="display:flex; gap:6px;">
              <button class="btn btn-secondary" style="padding:4px 10px; font-size:12px;" onclick="viewReport('${item._id}')"><i class="fas fa-eye"></i> View</button>
              <button class="btn btn-secondary" style="padding:4px 10px; font-size:12px;" onclick="downloadHistoryPdf('${item._id}')"><i class="fas fa-file-pdf"></i> PDF</button>
              <button class="btn btn-secondary" style="padding:4px 10px; font-size:12px;" onclick="investigateReport('${item._id}')"><i class="fas fa-crosshairs"></i> Investigate</button>
            </div>
          </td>
        </tr>
      `;
    }).join('');
  }

  window.downloadHistoryPdf = (id) => {
    const item = (allData || []).find(d => d._id === id || d.id === id);
    const params = item ? { scanId: item._id || item.id, target: item.target, scanType: item.scanType } : { scanId: id };
    downloadReportPDF(params, 'CyberShield_Scan_Report.pdf');
  };

  function filterData() {
    const search = (searchInput?.value || '').toLowerCase();
    const filter = filterSelect?.value || 'all';
    
    const filtered = allData.filter(item => {
      const matchSearch = (item.target || '').toLowerCase().includes(search);
      const matchFilter = filter === 'all' || item.status === filter;
      return matchSearch && matchFilter;
    });
    
    renderTable(filtered);
  }

  if (searchInput) searchInput.addEventListener('input', filterData);
  if (filterSelect) filterSelect.addEventListener('change', filterData);
  
  // View report — store data and redirect
  window.viewReport = (id) => {
    const item = (allData || []).find(d => d._id === id || d.id === id);
    if (item) {
      localStorage.setItem('lastScanData', JSON.stringify(item));
      window.location.href = `reports.html?id=${encodeURIComponent(id)}`;
    } else {
      window.location.href = `reports.html?id=${encodeURIComponent(id)}`;
    }
  };

  window.investigateReport = (id) => {
    const item = (allData || []).find(d => d._id === id || d.id === id);
    if (item) {
      localStorage.setItem('lastScanData', JSON.stringify(item));
      window.location.href = `investigation.html?scanId=${encodeURIComponent(id)}`;
    } else {
      window.location.href = `investigation.html?scanId=${encodeURIComponent(id)}`;
    }
  };

  // ─── CSV EXPORT ──────────────────────────────────────────────────
  const csvBtn = document.getElementById('export-csv-btn');
  if (csvBtn) {
    csvBtn.addEventListener('click', () => {
      if (!allData || allData.length === 0) {
        showToast('No data to export', 'warning');
        return;
      }

      const headers = ['Target', 'Type', 'Status', 'Risk Score', 'Date'];
      const rows = allData.map(item => [
        '"' + (item.target || '').replace(/"/g, '""') + '"',
        item.scanType || '',
        item.status || '',
        item.riskScore || 0,
        new Date(item.createdAt).toLocaleString()
      ]);

      const csvContent = [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
      const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `cybershield_scan_history_${new Date().toISOString().slice(0,10)}.csv`;
      a.click();
      URL.revokeObjectURL(url);
      showToast('CSV exported successfully', 'success');
    });
  }

  await loadHistory();
});
