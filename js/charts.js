/**
 * CyberShield AI — SOC Command Center Charts Engine
 */

const CHART_COLORS = {
  cyan:   '#00d4ff',
  green:  '#00c896',
  amber:  '#f59e0b',
  red:    '#ef4444',
  purple: '#8b5cf6',
  gray:   '#374151',
  blue:   '#3b82f6'
};

let scansBarChartInstance = null;
let riskLineChartInstance = null;

function renderScanActivityChart(chartData) {
  const ctx = document.getElementById('scansBarChart');
  if (!ctx) return;

  if (scansBarChartInstance) {
    scansBarChartInstance.destroy();
  }

  const labels = chartData?.labels || ['Mon','Tue','Wed','Thu','Fri','Sat','Sun'];
  const total = chartData?.total || [0,0,0,0,0,0,0];
  const threats = chartData?.threats || [0,0,0,0,0,0,0];
  const safe = chartData?.safe || [0,0,0,0,0,0,0];

  scansBarChartInstance = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: labels,
      datasets: [
        { label: 'Total Scans', data: total, backgroundColor: 'rgba(0, 212, 255, 0.6)', borderRadius: 4 },
        { label: 'Threats', data: threats, backgroundColor: 'rgba(239, 68, 68, 0.75)', borderRadius: 4 },
        { label: 'Safe Scans', data: safe, backgroundColor: 'rgba(0, 200, 150, 0.65)', borderRadius: 4 }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      interaction: { mode: 'index', intersect: false },
      plugins: {
        legend: { labels: { color: '#9ca3af', font: { size: 11, family: 'Inter' } } },
        tooltip: {
          backgroundColor: '#0b0f1a',
          borderColor: 'rgba(0, 212, 255, 0.3)',
          borderWidth: 1,
          titleColor: '#ffffff',
          bodyColor: '#9ca3af'
        }
      },
      scales: {
        x: { ticks: { color: '#6b7280', font: { size: 11 } }, grid: { color: 'rgba(255,255,255,0.03)' } },
        y: { ticks: { color: '#6b7280', precision: 0, font: { size: 11 } }, grid: { color: 'rgba(255,255,255,0.05)' }, beginAtZero: true }
      }
    }
  });
}

function renderScoreTrendChart(chartData) {
  const ctx = document.getElementById('riskLineChart');
  if (!ctx) return;

  if (riskLineChartInstance) {
    riskLineChartInstance.destroy();
  }

  const labels = chartData?.labels || ['Mon','Tue','Wed','Thu','Fri','Sat','Sun'];
  const scores = chartData?.scores || [80, 82, 78, 85, 88, 84, 86];

  riskLineChartInstance = new Chart(ctx, {
    type: 'line',
    data: {
      labels: labels,
      datasets: [{
        label: 'Security Score',
        data: scores,
        borderColor: CHART_COLORS.cyan,
        backgroundColor: 'rgba(0, 212, 255, 0.08)',
        borderWidth: 2,
        fill: true,
        tension: 0.35,
        pointBackgroundColor: CHART_COLORS.cyan,
        pointBorderColor: '#0b0f1a',
        pointRadius: 4,
        pointHoverRadius: 6
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: '#0b0f1a',
          borderColor: 'rgba(0, 212, 255, 0.3)',
          borderWidth: 1,
          callbacks: {
            label: (ctx) => `Score: ${ctx.parsed.y}/100`
          }
        }
      },
      scales: {
        x: { ticks: { color: '#6b7280', font: { size: 11 } }, grid: { display: false } },
        y: { ticks: { color: '#6b7280', font: { size: 11 } }, grid: { color: 'rgba(255,255,255,0.05)' }, min: 0, max: 100 }
      }
    }
  });
}
