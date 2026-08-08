/**
 * CyberShield AI — Threat Intelligence Logic
 */

document.addEventListener('DOMContentLoaded', () => {
  const lookupBtn = document.getElementById('lookup-btn');
  const iocInput = document.getElementById('ioc-input');
  const resultsDiv = document.getElementById('ti-results');
  
  if (lookupBtn && iocInput) {
    lookupBtn.addEventListener('click', async () => {
      const target = iocInput.value.trim();
      if (!target) {
        showToast('Please enter an IP or domain', 'warning');
        return;
      }
      
      const prevIcon = lookupBtn.innerHTML;
      lookupBtn.innerHTML = '<i class="fas fa-circle-notch fa-spin"></i> Analyzing...';
      lookupBtn.disabled = true;
      
      try {
        // We use the existing IP check endpoint
        const res = await apiRequest('/scan/ip', 'POST', { ip: target });
        
        lookupBtn.innerHTML = prevIcon;
        lookupBtn.disabled = false;
        
        if (res.success && res.data) {
          const data = res.data;
          resultsDiv.style.display = 'block';
          
          document.getElementById('ti-target').textContent = target;
          
          const riskLevel = data.riskLevel || 'Unknown';
          const badge = document.getElementById('ti-badge');
          badge.textContent = riskLevel;
          
          if (riskLevel.includes('High') || riskLevel.includes('Critical')) {
            badge.className = 'badge badge-danger';
          } else if (riskLevel.includes('Medium')) {
            badge.className = 'badge badge-warning';
          } else {
            badge.className = 'badge badge-safe';
          }
          
          document.getElementById('ti-isp').textContent = data.details?.isp || 'Unknown ISP';
          document.getElementById('ti-location').textContent = data.details?.location || 'Unknown Location';
          
          const abuseScore = data.threatScore || 0;
          document.getElementById('ti-reports').textContent = abuseScore > 50 ? `${abuseScore} Reports` : 'Clean';
        } else {
          showToast('Failed to retrieve intelligence data', 'danger');
        }
      } catch (err) {
        lookupBtn.innerHTML = prevIcon;
        lookupBtn.disabled = false;
        showToast('API connection error', 'danger');
      }
    });
    
    iocInput.addEventListener('keypress', (e) => {
      if (e.key === 'Enter') lookupBtn.click();
    });
  }
});
