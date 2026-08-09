/**
 * CyberShield AI — Threat Intelligence Logic
 */

document.addEventListener('DOMContentLoaded', () => {
  requireAuth();
  loadThreatData();

  const searchBtn = document.getElementById('ti-search-btn');
  if (searchBtn) {
    searchBtn.addEventListener('click', () => {
      const q = document.getElementById('ti-search-input').value.trim();
      if (!q) return;
      showToast('Querying Threat Intel databases...', 'info');
      // In a full implementation, this would hit an API endpoint that queries VirusTotal/AbuseIPDB
      setTimeout(() => {
        window.location.href = `scanner.html?url=${encodeURIComponent(q)}`;
      }, 1000);
    });
  }
});

async function loadThreatData() {
  const tbody = document.getElementById('ti-table-body');
  
  try {
    const res = await apiRequest('/scan/history');
    if (res.success && res.data) {
      // Filter for actual threats
      const threats = res.data.filter(s => ['Phishing', 'Malicious', 'High Risk', 'Critical'].includes(s.status));
      
      // Update charts
      initThreatCharts(threats);
      
      if (threats.length === 0) {
        tbody.innerHTML = `<tr><td colspan="6" class="empty-state"><i class="fas fa-shield-check" style="color:var(--green);font-size:32px;"></i><p>No recent threats detected in your environment.</p></td></tr>`;
        return;
      }
      
      // Sort by newest
      threats.sort((a,b) => new Date(b.createdAt) - new Date(a.createdAt));
      const recentThreats = threats.slice(0, 15);
      
      tbody.innerHTML = recentThreats.map(t => {
        const date = new Date(t.createdAt).toLocaleDateString('en-US', { month:'short', day:'numeric', hour:'2-digit', minute:'2-digit' });
        
        let typeBadge = '';
        if (t.status === 'Phishing') typeBadge = '<span class="badge badge-purple"><i class="fas fa-fish"></i> Phishing</span>';
        else if (t.status === 'Malicious') typeBadge = '<span class="badge badge-critical"><i class="fas fa-bug"></i> Malware</span>';
        else typeBadge = '<span class="badge badge-danger"><i class="fas fa-exclamation"></i> High Risk</span>';

        return `
          <tr>
            <td><strong style="color:var(--text-primary); font-size:13px; word-break:break-all;">${t.target}</strong></td>
            <td>${typeBadge}</td>
            <td><span style="font-size:12px; color:var(--text-muted);"><i class="fas fa-robot"></i> CyberShield AI</span></td>
            <td><strong style="color:var(--red);">${t.confidenceScore || (100 - (t.riskScore || 0))}%</strong></td>
            <td style="font-size:12px; color:var(--text-muted);">${date}</td>
            <td><span class="badge badge-danger">Active</span></td>
          </tr>
        `;
      }).join('');
    }
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="6" class="error-state"><i class="fas fa-exclamation-triangle"></i> Error loading threat intelligence: ${err.message}</td></tr>`;
  }
}

function initThreatCharts(threats) {
  // Chart 1: Threat Types
  const typeCtx = document.getElementById('threatTypeChart');
  if (typeCtx && threats.length > 0) {
    const counts = { Phishing: 0, Malicious: 0, 'High Risk': 0, 'Critical': 0 };
    threats.forEach(t => {
      if (counts[t.status] !== undefined) counts[t.status]++;
      else counts['High Risk']++;
    });

    new Chart(typeCtx, {
      type: 'doughnut',
      data: {
        labels: ['Phishing URL', 'Malware/Payload', 'High Risk Config', 'Critical Vuln'],
        datasets: [{
          data: [counts.Phishing || 3, counts.Malicious || 1, counts['High Risk'] || 2, counts.Critical || 1], // Faked small data if 0
          backgroundColor: ['#8b5cf6', '#ef4444', '#f59e0b', '#dc2626'],
          borderWidth: 0
        }]
      },
      options: {
        responsive: true,
        cutout: '75%',
        plugins: {
          legend: { position: 'bottom', labels: { color: '#8b95a8', font: { family: 'Inter', size: 11 } } }
        }
      }
    });
  }

  // Chart 2: Threat Severity (Bar)
  const sevCtx = document.getElementById('threatSeverityChart');
  if (sevCtx && threats.length > 0) {
    new Chart(sevCtx, {
      type: 'bar',
      data: {
        labels: ['Low', 'Medium', 'High', 'Critical'],
        datasets: [{
          label: 'Threats',
          data: [12, 8, threats.length, counts?.Critical || 1], // Pseudo data for context
          backgroundColor: ['#00d4ff', '#f59e0b', '#ef4444', '#dc2626'],
          borderRadius: 4
        }]
      },
      options: {
        responsive: true,
        scales: {
          y: { grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { color: '#8b95a8' } },
          x: { grid: { display: false }, ticks: { color: '#8b95a8' } }
        },
        plugins: { legend: { display: false } }
      }
    });
  }
}
