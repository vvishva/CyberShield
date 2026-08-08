/**
 * CyberShield AI — Notifications Logic
 */

document.addEventListener('DOMContentLoaded', async () => {
  const notifList = document.getElementById('notifications-list');
  const markReadBtn = document.getElementById('mark-all-read-btn');
  
  async function loadNotifications() {
    try {
      // Mock data for UI demonstration purposes as backend route might need expansion
      const mockData = [
        { _id: '1', type: 'ALERT', title: 'High Risk Phishing Detected', message: 'User attempted to scan a known phishing domain (paypal-security-update-alert.com).', isRead: false, createdAt: new Date(Date.now() - 3600000) },
        { _id: '2', type: 'INFO', title: 'System Update', message: 'CyberBot AI has been updated to v2.1 with improved threat recognition.', isRead: true, createdAt: new Date(Date.now() - 86400000) },
        { _id: '3', type: 'WARNING', title: 'Multiple Failed Logins', message: '3 failed login attempts detected from IP 104.28.19.44.', isRead: false, createdAt: new Date(Date.now() - 172800000) }
      ];
      
      renderNotifications(mockData);
    } catch (e) {
      console.error(e);
    }
  }

  function renderNotifications(data) {
    if (!data || data.length === 0) return;
    
    notifList.innerHTML = data.map(item => {
      const icon = item.type === 'ALERT' ? 'fa-exclamation-circle text-danger' : 
                   item.type === 'WARNING' ? 'fa-exclamation-triangle text-warning' : 'fa-info-circle text-info';
      const color = item.type === 'ALERT' ? 'var(--neon-red)' : 
                    item.type === 'WARNING' ? 'var(--neon-amber)' : 'var(--neon-cyan)';
      const bg = item.isRead ? 'rgba(255,255,255,0.02)' : `rgba(${item.type==='ALERT'?'255,0,85':item.type==='WARNING'?'255,183,0':'0,240,255'},0.08)`;
      const border = item.isRead ? 'var(--border-glass)' : color;
      
      const time = new Date(item.createdAt).toLocaleString();
      
      return `
        <div style="padding:16px; border-left:4px solid ${border}; background:${bg}; border-radius:4px; display:flex; gap:16px; align-items:flex-start;">
          <i class="fas ${icon}" style="font-size:20px; color:${color}; margin-top:2px;"></i>
          <div style="flex:1;">
            <div style="display:flex; justify-content:space-between; margin-bottom:4px;">
              <h4 style="color:#fff;">${item.title}</h4>
              <span style="font-size:12px; color:var(--text-muted);">${time}</span>
            </div>
            <p style="font-size:13px; color:var(--text-muted);">${item.message}</p>
          </div>
        </div>
      `;
    }).join('');
  }

  if (markReadBtn) {
    markReadBtn.addEventListener('click', () => {
      showToast('All notifications marked as read', 'success');
      loadNotifications(); // Reload to show read state
    });
  }

  await loadNotifications();
});
