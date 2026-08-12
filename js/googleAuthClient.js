/**
 * CyberShield — Official Google Identity Services Client
 * Optimized for Desktop and Mobile Browsers (Android / iOS / Chrome / Safari).
 */

(function () {
  const GOOGLE_CLIENT_ID = window.GOOGLE_CLIENT_ID || '216593256191-jc2kvjrfjt4ounthofpph92q65pct9n4.apps.googleusercontent.com';

  function initGoogleSSO() {
    const googleBtn = document.getElementById('btn-google-sso');
    if (!googleBtn) return;

    googleBtn.addEventListener('click', onGoogleBtnClicked);

    // Global PostMessage listener for popup authorization events
    window.addEventListener('message', handleGlobalAuthMessage);

    // Storage Event listener for cross-tab session sync (Mobile + Desktop)
    window.addEventListener('storage', (e) => {
      if (e.key === 'cybershield_token' && e.newValue) {
        showToast('✓ Authentication successful! Opening Dashboard...', 'success');
        setTimeout(() => {
          window.location.replace('dashboard.html');
        }, 200);
      }
    });

    // Initialize GIS if SDK loaded
    if (window.google && window.google.accounts && window.google.accounts.id) {
      try {
        window.google.accounts.id.initialize({
          client_id: GOOGLE_CLIENT_ID,
          callback: (res) => handleGoogleCredentialResponse(res),
          auto_select: false
        });
      } catch (e) {}
    }
  }

  function handleGlobalAuthMessage(event) {
    if (!event.data) return;

    if (event.data.type === 'GOOGLE_AUTH_SUCCESS' && event.data.token) {
      setToken(event.data.token, true);
      if (event.data.user) setUser(event.data.user, true);

      const googleBtn = document.getElementById('btn-google-sso');
      if (googleBtn) {
        googleBtn.innerHTML = '<i class="fas fa-check-circle" style="color:#00c896;"></i> Authentication successful';
        googleBtn.disabled = true;
      }

      showToast('✓ Authentication successful! Opening Dashboard...', 'success');
      setTimeout(() => {
        window.location.replace('dashboard.html');
      }, 300);
    } else if (event.data.type === 'GOOGLE_AUTH_CREDENTIAL' && event.data.credential) {
      const googleBtn = document.getElementById('btn-google-sso');
      verifyWithBackend({ credential: event.data.credential }, googleBtn, googleBtn ? googleBtn.innerHTML : '');
    } else if (event.data.type === 'GOOGLE_AUTH_CANCELLED') {
      const googleBtn = document.getElementById('btn-google-sso');
      if (googleBtn && googleBtn.disabled && googleBtn.innerHTML.includes('Connecting')) {
        setGoogleBtnLoading(googleBtn, false, '<svg viewBox="0 0 24 24"><path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/><path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/><path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.06H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.94l2.85-2.22.81-.63z"/><path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.06l3.66 2.84c.87-2.6 3.3-4.52 6.16-4.52z"/></svg> Continue with Google');
        showToast('Google sign-in was cancelled.', 'info');
      }
    }
  }

  function onGoogleBtnClicked(e) {
    if (e) e.preventDefault();
    const googleBtn = document.getElementById('btn-google-sso');
    if (!googleBtn) return;

    const originalHTML = googleBtn.innerHTML;
    setGoogleBtnLoading(googleBtn, true);

    // Strategy 1: GIS Native Token Client (Mobile + Desktop)
    if (window.google && window.google.accounts && window.google.accounts.oauth2) {
      try {
        const tokenClient = window.google.accounts.oauth2.initTokenClient({
          client_id: GOOGLE_CLIENT_ID,
          scope: 'email profile openid',
          callback: async (tokenResponse) => {
            if (tokenResponse && (tokenResponse.access_token || tokenResponse.id_token)) {
              await verifyWithBackend({
                token: tokenResponse.access_token,
                credential: tokenResponse.id_token
              }, googleBtn, originalHTML);
            } else {
              setGoogleBtnLoading(googleBtn, false, originalHTML);
              showToast('Google sign-in was cancelled.', 'info');
            }
          },
          error_callback: () => {
            setGoogleBtnLoading(googleBtn, false, originalHTML);
            showToast('Google sign-in was cancelled.', 'info');
          }
        });

        tokenClient.requestAccessToken({ prompt: 'select_account' });
        return;
      } catch (e) {}
    }

    // Strategy 2: GIS ID Prompt
    if (window.google && window.google.accounts && window.google.accounts.id) {
      try {
        window.google.accounts.id.initialize({
          client_id: GOOGLE_CLIENT_ID,
          callback: (res) => handleGoogleCredentialResponse(res, googleBtn, originalHTML),
          auto_select: false
        });

        window.google.accounts.id.prompt((notification) => {
          if (notification.isDismissedMoment()) {
            setGoogleBtnLoading(googleBtn, false, originalHTML);
            showToast('Google sign-in was cancelled.', 'info');
          } else if (notification.isNotDisplayed()) {
            openGoogleOAuthPopup(googleBtn, originalHTML);
          }
        });
        return;
      } catch (err) {}
    }

    // Strategy 3: Web Popup Fallback
    openGoogleOAuthPopup(googleBtn, originalHTML);
  }

  function openGoogleOAuthPopup(googleBtn, originalHTML) {
    const redirectUri = window.location.origin + '/client/google-callback.html';
    const googleAuthUrl = `https://accounts.google.com/o/oauth2/v2/auth?` +
      `client_id=${encodeURIComponent(GOOGLE_CLIENT_ID)}` +
      `&redirect_uri=${encodeURIComponent(redirectUri)}` +
      `&response_type=id_token` +
      `&scope=${encodeURIComponent('openid email profile')}` +
      `&nonce=${Date.now()}` +
      `&prompt=select_account`;

    const width = 520;
    const height = 640;
    const left = Math.max(0, (window.screen.width - width) / 2);
    const top = Math.max(0, (window.screen.height - height) / 2);

    let popup = null;
    try {
      popup = window.open(
        googleAuthUrl,
        'GoogleAuthPopup',
        `width=${width},height=${height},top=${top},left=${left},scrollbars=yes,status=1,resizable=1`
      );
    } catch (e) {
      popup = null;
    }

    if (!popup) {
      setGoogleBtnLoading(googleBtn, false, originalHTML);
      showToast('Popup blocked. Click "Continue with Google" again or allow popups.', 'warning');
      return;
    }

    const popupCheckInterval = setInterval(() => {
      try {
        if (!popup || popup.closed) {
          clearInterval(popupCheckInterval);
          if (googleBtn && googleBtn.disabled && googleBtn.innerHTML.includes('Connecting')) {
            setGoogleBtnLoading(googleBtn, false, originalHTML);
            showToast('Google sign-in was cancelled.', 'info');
          }
        }
      } catch (e) {}
    }, 600);
  }

  async function handleGoogleCredentialResponse(response, googleBtn, originalHTML) {
    const btn = googleBtn || document.getElementById('btn-google-sso');
    if (response && response.credential) {
      await verifyWithBackend({ credential: response.credential }, btn, originalHTML);
    } else {
      if (btn) setGoogleBtnLoading(btn, false, originalHTML);
      showToast('Google authentication could not be verified.', 'danger');
    }
  }

  async function verifyWithBackend(payload, googleBtn, originalHTML) {
    const btn = googleBtn || document.getElementById('btn-google-sso');
    try {
      if (btn) setGoogleBtnLoading(btn, true);
      showToast('Verifying Google credential with CyberShield backend...', 'info');

      const data = await apiRequest('/auth/google', 'POST', payload);

      if (data.success && data.token) {
        setToken(data.token, true);
        setUser(data.user, true);

        if (btn) {
          btn.innerHTML = '<i class="fas fa-check-circle" style="color:#00c896;"></i> Authentication successful';
          btn.disabled = true;
        }

        showToast('Authentication successful! Opening Dashboard...', 'success');
        setTimeout(() => {
          window.location.replace('dashboard.html');
        }, 300);
      } else {
        if (btn) setGoogleBtnLoading(btn, false, originalHTML);
        showToast(data.error || 'Google authentication could not be verified.', 'danger');
      }
    } catch (err) {
      if (btn) setGoogleBtnLoading(btn, false, originalHTML);
      showToast(err.message || 'Unable to sign in with Google. Please try again.', 'danger');
    }
  }

  function setGoogleBtnLoading(btn, isLoading, originalHTML) {
    if (!btn) return;
    if (isLoading) {
      btn.disabled = true;
      btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Connecting to Google...';
    } else {
      btn.disabled = false;
      if (originalHTML) btn.innerHTML = originalHTML;
    }
  }

  window.handleGoogleCredentialResponse = handleGoogleCredentialResponse;
  window.performGoogleAuthToken = verifyWithBackend;

  document.addEventListener('DOMContentLoaded', initGoogleSSO);
})();
