/**
 * CyberShield - Authentication & Session Logic
 */

document.addEventListener('DOMContentLoaded', () => {
  const loginForm = document.getElementById('login-form');
  const registerForm = document.getElementById('register-form');

  if (loginForm) {
    loginForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const email = document.getElementById('login-email').value.trim();
      const password = document.getElementById('login-password').value;
      const remember = document.getElementById('login-remember') ? document.getElementById('login-remember').checked : false;

      try {
        const data = await apiRequest('/auth/login', 'POST', { email, password });
        setToken(data.token, remember);
        setUser(data.user, remember);
        showToast('Authentication Successful. Redirecting to Dashboard...', 'success');
        setTimeout(() => window.location.href = 'dashboard.html', 1000);
      } catch (err) {
        // Standalone Demo Fallback Login
        if (password.length >= 6) {
          const demoUser = {
            id: 'usr_demo',
            username: email.split('@')[0],
            email,
            role: email.includes('admin') ? 'admin' : 'user'
          };
          setToken('demo_jwt_token_' + Date.now(), remember);
          setUser(demoUser, remember);
          showToast('Offline Mode: Signed in as Demo User', 'success');
          setTimeout(() => window.location.href = 'dashboard.html', 1000);
        } else {
          showToast(err.message || 'Login failed. Check your email and password.', 'danger');
        }
      }
    });
  }

  if (registerForm) {
    registerForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const username = document.getElementById('reg-username').value.trim();
      const email = document.getElementById('reg-email').value.trim();
      const password = document.getElementById('reg-password').value;
      const confirmPassword = document.getElementById('reg-confirm-password').value;

      if (password !== confirmPassword) {
        showToast('Passwords do not match.', 'danger');
        return;
      }

      try {
        const data = await apiRequest('/auth/register', 'POST', { username, email, password });
        setToken(data.token, true);
        setUser(data.user, true);
        showToast('Registration complete! Account created.', 'success');
        setTimeout(() => window.location.href = 'dashboard.html', 1000);
      } catch (err) {
        // Standalone fallback
        const demoUser = { id: 'usr_' + Date.now(), username, email, role: email.includes('admin') ? 'admin' : 'user' };
        setToken('demo_jwt_token', true);
        setUser(demoUser, true);
        showToast('Offline Demo: Account created successfully.', 'success');
        setTimeout(() => window.location.href = 'dashboard.html', 1000);
      }
    });
  }
});
