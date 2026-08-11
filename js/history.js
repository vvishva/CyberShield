/**
 * CyberShield AI — Scan History Controller
 * Manages scan history table, filtering, CSV exports, PDF downloads, and navigation handlers.
 */

// Global state store accessible by inline handlers and event delegation
window.historyScanStore = [];

// ── Global Window Handlers (Exposed immediately for inline onclick handlers) ─
window.viewReport = async function(id) {
  if (!id) return;
  let item = (window.historyScanStore || []).find(d => String(d._id) === String(id) || String(d.id) === String(id));
  
  if (!item) {
    try {
      const res = await apiRequest('/scan/history');
      if (res.success && res.data) {
        window.historyScanStore = res.data;
        item = res.data.find(d => String(d._id) === String(id) || String(d.id) === String(id));
      }
    } catch(e) {}
  }

  if (item) {
    localStorage.setItem('lastScanData', JSON.stringify(item));
  }
  window.location.href = `reports.html?id=${encodeURIComponent(id)}`;
};

window.investigateReport = async function(id) {
  if (!id) return;
  let item = (window.historyScanStore || []).find(d => String(d._id) === String(id) || String(d.id) === String(id));
  
  if (!item) {
    try {
      const res = await apiRequest('/scan/history');
      if (res.success && res.data) {
        window.historyScanStore = res.data;
        item = res.data.find(d => String(d._id) === String(id) || String(d.id) === String(id));
      }
    } catch(e) {}
  }

  if (item) {
    localStorage.setItem('lastScanData', JSON.stringify(item));
  }
  window.location.href = `investigation.html?scanId=${encodeURIComponent(id)}`;
};

window.downloadHistoryPdf = async function(id) {
  if (!id) return;
  let item = (window.historyScanStore || []).find(d => String(d._id) === String(id) || String(d.id) === String(id));
  const params = item ? { scanId: item._id || item.id, target: item.target, scanType: item.scanType } : { scanId: id };
  downloadReportPDF(params, 'CyberShield_Scan_Report.pdf');
};

document.addEventListener('DOMContentLoaded', async () => {
  requireAuth();

  const tableBody = document.getElementById('history-table-body');
  const searchInput = document.getElementById('history-search');
  const filterSelect = document.getElementById('history-filter');

  async function loadHistory() {
    try {
      const res = await apiRequest('/scan/history');
      if (res.success && res.data) {
        window.historyScanStore = res.data;
        renderTable(window.historyScanStore);
      } else {
        tableBody.innerHTML = '<tr><td colspan="6" style="text-align:center; color:var(--text-muted);">No scan history found</td></tr>';
      }
    } catch (e) {
      console.error('[History Load Error]', e);
      tableBody.innerHTML = '<tr><td colspan="6" style="text-align:center; color:var(--red);">Failed to load history</td></tr>';
    }
  }

  function renderTable(data) {
    if (!data || data.length === 0) {
      tableBody.innerHTML = '<tr><td colspan="6" style="text-align:center; color:var(--text-muted);">No scan history found</td></tr>';
      return;
    }
    
    tableBody.innerHTML = data.map(item => {
      const itemId = item._id || item.id || '';
      const time = item.createdAt ? new Date(item.createdAt).toLocaleString() : 'Recent';
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
          <td><span class="badge ${badgeClass}">${escapeHtml(item.status || 'Scanned')}</span></td>
          <td><span style="color:${isThreat ? 'var(--red)' : 'var(--green)'}; font-weight:600;">${item.riskScore || 0}% Risk</span></td>
          <td style="color:var(--text-muted); font-size:13px;">${time}</td>
          <td>
            <div style="display:flex; gap:6px; flex-wrap:nowrap;">
              <button class="btn btn-secondary btn-sm" data-action="view" data-id="${itemId}" style="padding:4px 10px; font-size:12px; cursor:pointer;" onclick="viewReport('${itemId}')"><i class="fas fa-eye"></i> View</button>
              <button class="btn btn-secondary btn-sm" data-action="pdf" data-id="${itemId}" style="padding:4px 10px; font-size:12px; cursor:pointer;" onclick="downloadHistoryPdf('${itemId}')"><i class="fas fa-file-pdf"></i> PDF</button>
              <button class="btn btn-secondary btn-sm" data-action="investigate" data-id="${itemId}" style="padding:4px 10px; font-size:12px; cursor:pointer;" onclick="investigateReport('${itemId}')"><i class="fas fa-crosshairs"></i> Investigate</button>
            </div>
          </td>
        </tr>
      `;
    }).join('');
  }

  // ── Event Delegation Listener for Table Buttons ─────────────────────────────
  if (tableBody) {
    tableBody.addEventListener('click', (e) => {
      const btn = e.target.closest('button[data-action]');
      if (!btn) return;
      
      const action = btn.getAttribute('data-action');
      const id = btn.getAttribute('data-id');
      if (!id) return;

      if (action === 'view') {
        window.viewReport(id);
      } else if (action === 'pdf') {
        window.downloadHistoryPdf(id);
      } else if (action === 'investigate') {
        window.investigateReport(id);
      }
    });
  }

  function filterData() {
    const search = (searchInput?.value || '').toLowerCase();
    const filter = filterSelect?.value || 'all';
    
    const filtered = (window.historyScanStore || []).filter(item => {
      const matchSearch = (item.target || '').toLowerCase().includes(search);
      const matchFilter = filter === 'all' || item.status === filter;
      return matchSearch && matchFilter;
    });
    
    renderTable(filtered);
  }

  if (searchInput) searchInput.addEventListener('input', filterData);
  if (filterSelect) filterSelect.addEventListener('change', filterData);

  // ── CSV EXPORT ─────────────────────────────────────────────────────────────
  const csvBtn = document.getElementById('export-csv-btn');
  if (csvBtn) {
    csvBtn.addEventListener('click', () => {
      const dataToExport = window.historyScanStore || [];
      if (dataToExport.length === 0) {
        showToast('No scan history data to export', 'warning');
        return;
      }

      const headers = ['Target', 'Type', 'Status', 'Risk Score', 'Date'];
      const rows = dataToExport.map(item => [
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
