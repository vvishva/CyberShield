/**
 * CyberShield — Official Google Identity Services & OAuth 2.0 Client
 *
 * Implements Google's official Account Chooser flow via Google Identity Services
 * and fallback OAuth 2.0 Web Authorization Popup.
 */

(function () {
  const GOOGLE_CLIENT_ID = window.GOOGLE_CLIENT_ID || '216593256191-jc2kvjrfjt4ounthofpph92q65pct9n4.apps.googleusercontent.com';

  function initGoogleSSO() {
    const googleBtn = document.getElementById('btn-google-sso');
    if (!googleBtn) return;

    // Attach click handler immediately
    googleBtn.addEventListener('click', onGoogleBtnClicked);

    // Initialize GIS if script already loaded
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

    // Strategy 1: Check if Google Identity Services SDK is ready
    if (window.google && window.google.accounts && window.google.accounts.id) {
      try {
        window.google.accounts.id.initialize({
          client_id: GOOGLE_CLIENT_ID,
          callback: (res) => handleGoogleCredentialResponse(res, googleBtn, originalHTML),
          auto_select: false
        });

        let promptShowed = false;
        window.google.accounts.id.prompt((notification) => {
          promptShowed = true;
          if (notification.isDismissedMoment()) {
            setGoogleBtnLoading(googleBtn, false, originalHTML);
            showToast('Google sign-in was cancelled.', 'info');
          } else if (notification.isNotDisplayed() || notification.isSkippedMoment()) {
            openGoogleOAuthPopup(googleBtn, originalHTML);
          }
        });

        // Fallback to popup if prompt is suppressed or quiet
        setTimeout(() => {
          if (!promptShowed && googleBtn.disabled && googleBtn.innerHTML.includes('Connecting')) {
            openGoogleOAuthPopup(googleBtn, originalHTML);
          }
        }, 1200);

        return;
      } catch (err) {
        console.warn('[GIS Prompt Fallback]:', err);
      }
    }

    // Strategy 2: Direct Official Google OAuth 2.0 Web Popup
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

    // Monitor popup window status
    const popupCheckInterval = setInterval(() => {
      try {
        if (!popup || popup.closed) {
          clearInterval(popupCheckInterval);
          window.removeEventListener('message', handleMessage);
          if (googleBtn && googleBtn.disabled && googleBtn.innerHTML.includes('Connecting')) {
            setGoogleBtnLoading(googleBtn, false, originalHTML);
            showToast('Google sign-in was cancelled.', 'info');
          }
        }
      } catch (e) {}
    }, 600);

    async function handleMessage(event) {
      if (event.data && event.data.type === 'GOOGLE_AUTH_CREDENTIAL' && event.data.credential) {
        clearInterval(popupCheckInterval);
        window.removeEventListener('message', handleMessage);
        if (popup && !popup.closed) {
          try { popup.close(); } catch (e) {}
        }
        await verifyWithBackend({ credential: event.data.credential }, googleBtn, originalHTML);
      } else if (event.data && event.data.type === 'GOOGLE_AUTH_CANCELLED') {
        clearInterval(popupCheckInterval);
        window.removeEventListener('message', handleMessage);
        if (popup && !popup.closed) {
          try { popup.close(); } catch (e) {}
        }
        setGoogleBtnLoading(googleBtn, false, originalHTML);
        showToast('Google sign-in was cancelled.', 'info');
      }
    }

    window.addEventListener('message', handleMessage);
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
