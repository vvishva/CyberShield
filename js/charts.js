/**
 * CyberShield - Chart.js Visual Graphs Controller
 */

function initDashboardCharts() {
  const pieCtx = document.getElementById('threatPieChart');
  const barCtx = document.getElementById('scansBarChart');
  const lineCtx = document.getElementById('riskLineChart');

  if (pieCtx && typeof Chart !== 'undefined') {
    new Chart(pieCtx, {
      type: 'doughnut',
      data: {
        labels: ['Safe Websites', 'Suspicious URLs', 'Phishing Threats', 'Weak Passwords'],
        datasets: [{
          data: [62, 18, 12, 8],
          backgroundColor: [
            '#00ff9d',
            '#ffb700',
            '#ff0055',
            '#8a2be2'
          ],
          borderColor: '#08090e',
          borderWidth: 3
        }]
      },
      options: {
        responsive: true,
        plugins: {
          legend: {
            position: 'bottom',
            labels: { color: '#8e9bb0', font: { family: 'Inter' } }
          }
        }
      }
    });
  }

  if (barCtx && typeof Chart !== 'undefined') {
    new Chart(barCtx, {
      type: 'bar',
      data: {
        labels: ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug'],
        datasets: [
          {
            label: 'Total Security Scans',
            data: [120, 190, 300, 250, 420, 380, 510, 640],
            backgroundColor: 'rgba(0, 240, 255, 0.6)',
            borderColor: '#00f0ff',
            borderWidth: 1,
            borderRadius: 6
          },
          {
            label: 'Blocked Threats',
            data: [20, 45, 80, 50, 95, 85, 110, 140],
            backgroundColor: 'rgba(255, 0, 85, 0.6)',
            borderColor: '#ff0055',
            borderWidth: 1,
            borderRadius: 6
          }
        ]
      },
      options: {
        responsive: true,
        scales: {
          x: { ticks: { color: '#8e9bb0' }, grid: { color: 'rgba(255,255,255,0.05)' } },
          y: { ticks: { color: '#8e9bb0' }, grid: { color: 'rgba(255,255,255,0.05)' } }
        },
        plugins: {
          legend: { labels: { color: '#8e9bb0' } }
        }
      }
    });
  }

  if (lineCtx && typeof Chart !== 'undefined') {
    new Chart(lineCtx, {
      type: 'line',
      data: {
        labels: ['Week 1', 'Week 2', 'Week 3', 'Week 4'],
        datasets: [{
          label: 'Average Risk Percentage (%)',
          data: [42, 35, 28, 18],
          borderColor: '#8a2be2',
          backgroundColor: 'rgba(138, 43, 226, 0.2)',
          fill: true,
          tension: 0.4,
          pointRadius: 6,
          pointBackgroundColor: '#00f0ff'
        }]
      },
      options: {
        responsive: true,
        scales: {
          x: { ticks: { color: '#8e9bb0' }, grid: { color: 'rgba(255,255,255,0.05)' } },
          y: { min: 0, max: 100, ticks: { color: '#8e9bb0' }, grid: { color: 'rgba(255,255,255,0.05)' } }
        },
        plugins: {
          legend: { labels: { color: '#8e9bb0' } }
        }
      }
    });
  }
}
