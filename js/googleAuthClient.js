/**
 * CyberShield — Official Google Identity Services & OAuth 2.0 Client
 * Uses Google Identity Services GIS SDK native popup flow.
 */

(function () {
  const GOOGLE_CLIENT_ID = window.GOOGLE_CLIENT_ID || '216593256191-jc2kvjrfjt4ounthofpph92q65pct9n4.apps.googleusercontent.com';

  function initGoogleSSO() {
    const googleBtn = document.getElementById('btn-google-sso');
    if (!googleBtn) return;

    googleBtn.addEventListener('click', onGoogleBtnClicked);

    if (window.google && window.google.accounts && window.google.accounts.id) {
      try {
        window.google.accounts.id.initialize({
          client_id: GOOGLE_CLIENT_ID,
          callback: handleGoogleCredentialResponse,
          auto_select: false
        });
      } catch (e) {}
    }
  }

  function onGoogleBtnClicked(e) {
    if (e) e.preventDefault();
    const googleBtn = document.getElementById('btn-google-sso');
    if (!googleBtn) return;

    const originalHTML = googleBtn.innerHTML;
    setGoogleBtnLoading(googleBtn, true);

    // Strategy 1: Use Google Identity Services Native Token Client (Popup)
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
          error_callback: (err) => {
            setGoogleBtnLoading(googleBtn, false, originalHTML);
            showToast('Google sign-in was cancelled.', 'info');
          }
        });

        tokenClient.requestAccessToken({ prompt: 'select_account' });
        return;
      } catch (err) {
        console.warn('[GIS TokenClient Fallback]:', err);
      }
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
    const redirectUri = window.location.origin + '/client/login.html';
    const googleAuthUrl = `https://accounts.google.com/o/oauth2/v2/auth?` +
      `client_id=${encodeURIComponent(GOOGLE_CLIENT_ID)}` +
      `&redirect_uri=${encodeURIComponent(redirectUri)}` +
      `&response_type=token%20id_token` +
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
        setToken(data.token);
        setUser(data.user);

        if (btn) {
          btn.innerHTML = '<i class="fas fa-check-circle" style="color:#00c896;"></i> Authentication successful';
          btn.disabled = true;
        }

        showToast('Authentication successful! Redirecting to Dashboard...', 'success');
        setTimeout(() => {
          window.location.href = 'dashboard.html';
        }, 1000);
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
