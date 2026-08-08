/**
 * CyberShield AI — Chart Initialization
 */

const CHART_COLORS = {
  cyan:   '#00d4ff',
  green:  '#00c896',
  amber:  '#f59e0b',
  red:    '#ef4444',
  purple: '#8b5cf6',
  gray:   '#374151'
};

function initDashboardCharts(stats) {
  initThreatPieChart(stats);
  initScansBarChart();
  initRiskLineChart();
}

function initThreatPieChart(stats) {
  const ctx = document.getElementById('threatPieChart');
  if (!ctx) return;
  const safe = stats?.safeScans || 940;
  const threats = stats?.threatsDetected || 318;
  const suspicious = Math.round(threats * 0.35);
  const phishing = Math.round(threats * 0.40);
  const ssl = Math.round(threats * 0.15);
  const weak = Math.round(threats * 0.10);
  new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: ['Safe', 'Suspicious', 'Phishing', 'SSL Issues', 'Weak Password'],
      datasets: [{ data: [safe, suspicious, phishing, ssl, weak],
        backgroundColor: [CHART_COLORS.green, CHART_COLORS.amber, CHART_COLORS.red, CHART_COLORS.purple, CHART_COLORS.cyan],
        borderWidth: 0, hoverOffset: 6 }]
    },
    options: {
      responsive: true, maintainAspectRatio: false, cutout: '65%',
      plugins: { legend: { position: 'bottom', labels: { color: '#9ca3af', padding: 12, font: { size: 12 } } } }
    }
  });
}

function initScansBarChart() {
  const ctx = document.getElementById('scansBarChart');
  if (!ctx) return;
  const months = ['Feb','Mar','Apr','May','Jun','Jul','Aug'];
  new Chart(ctx, {
    type: 'bar',
    data: {
      labels: months,
      datasets: [
        { label: 'Total Scans', data: [120,185,210,178,240,195,354], backgroundColor: 'rgba(0,212,255,0.6)', borderRadius: 4 },
        { label: 'Threats', data: [18,32,45,28,62,48,85], backgroundColor: 'rgba(239,68,68,0.7)', borderRadius: 4 }
      ]
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      plugins: { legend: { labels: { color: '#9ca3af' } } },
      scales: {
        x: { ticks: { color: '#6b7280' }, grid: { color: 'rgba(255,255,255,0.05)' } },
        y: { ticks: { color: '#6b7280' }, grid: { color: 'rgba(255,255,255,0.05)' } }
      }
    }
  });
}

function initRiskLineChart() {
  const ctx = document.getElementById('riskLineChart');
  if (!ctx) return;
  const days = ['Mon','Tue','Wed','Thu','Fri','Sat','Sun'];
  new Chart(ctx, {
    type: 'line',
    data: {
      labels: days,
      datasets: [{
        label: 'Risk Score (avg)',
        data: [42,38,55,30,48,35,28],
        borderColor: CHART_COLORS.cyan,
        backgroundColor: 'rgba(0,212,255,0.08)',
        fill: true, tension: 0.4, pointBackgroundColor: CHART_COLORS.cyan
      }]
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      plugins: { legend: { labels: { color: '#9ca3af' } } },
      scales: {
        x: { ticks: { color: '#6b7280' }, grid: { display: false } },
        y: { ticks: { color: '#6b7280' }, grid: { color: 'rgba(255,255,255,0.05)' }, min: 0, max: 100 }
      }
    }
  });
}
