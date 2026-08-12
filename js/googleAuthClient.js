/**
 * CyberShield — Official Google Identity Services & OAuth 2.0 Client
 * Handles real Google Authentication flow for Login & Registration pages.
 */

(function () {
  // Google Client ID (configurable via window.GOOGLE_CLIENT_ID or environment)
  const GOOGLE_CLIENT_ID = window.GOOGLE_CLIENT_ID || '829471928471-cybershield.apps.googleusercontent.com';

  function initGoogleSSO() {
    const googleBtn = document.getElementById('btn-google-sso');
    if (!googleBtn) return;

    // Check if Google Identity Services SDK loaded
    if (typeof google !== 'undefined' && google.accounts && google.accounts.id) {
      try {
        google.accounts.id.initialize({
          client_id: GOOGLE_CLIENT_ID,
          callback: handleGoogleCredentialResponse,
          auto_select: false,
          cancel_on_tap_outside: true
        });
      } catch (e) {
        console.warn('[Google GIS Init Warning]:', e.message);
      }
    }

    googleBtn.addEventListener('click', onGoogleBtnClicked);
  }

  async function onGoogleBtnClicked(e) {
    e.preventDefault();
    const googleBtn = document.getElementById('btn-google-sso');
    if (!googleBtn) return;

    const originalHTML = googleBtn.innerHTML;
    setGoogleBtnLoading(googleBtn, true);

    try {
      // Strategy A: Check if official Google Identity Services SDK is available
      if (typeof google !== 'undefined' && google.accounts && google.accounts.id) {
        // Trigger Google's official Account Chooser prompt
        google.accounts.id.prompt((notification) => {
          if (notification.isNotDisplayed() || notification.isSkippedMoment_()) {
            // Fallback to Google OAuth Token Client popup if prompt is suppressed
            triggerGoogleOAuthPopup(googleBtn, originalHTML);
          } else if (notification.isDismissedMoment()) {
            setGoogleBtnLoading(googleBtn, false, originalHTML);
            showToast('Google sign-in was cancelled.', 'info');
          }
        });
      } else {
        // Strategy B: Fallback Google OAuth Popup
        triggerGoogleOAuthPopup(googleBtn, originalHTML);
      }
    } catch (err) {
      setGoogleBtnLoading(googleBtn, false, originalHTML);
      showToast('Unable to sign in with Google. Please try again.', 'danger');
    }
  }

  function triggerGoogleOAuthPopup(googleBtn, originalHTML) {
    if (typeof google !== 'undefined' && google.accounts && google.accounts.oauth2) {
      const client = google.accounts.oauth2.initTokenClient({
        client_id: GOOGLE_CLIENT_ID,
        scope: 'email profile openid',
        callback: async (tokenResponse) => {
          if (tokenResponse && tokenResponse.access_token) {
            await verifyWithBackend({ token: tokenResponse.access_token }, googleBtn, originalHTML);
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
      client.requestAccessToken();
    } else {
      // Modal Chooser Fallback (Safe fallback for local dev / unconfigured origins)
      const modal = document.getElementById('google-sso-modal');
      if (modal) {
        setGoogleBtnLoading(googleBtn, false, originalHTML);
        modal.classList.add('active');
      } else {
        setGoogleBtnLoading(googleBtn, false, originalHTML);
        showToast('Unable to connect to Google OAuth service.', 'warning');
      }
    }
  }

  async function handleGoogleCredentialResponse(response) {
    const googleBtn = document.getElementById('btn-google-sso');
    const originalHTML = googleBtn ? googleBtn.innerHTML : '';
    if (response && response.credential) {
      await verifyWithBackend({ credential: response.credential }, googleBtn, originalHTML);
    } else {
      if (googleBtn) setGoogleBtnLoading(googleBtn, false, originalHTML);
      showToast('Google authentication could not be verified.', 'danger');
    }
  }

  async function verifyWithBackend(payload, googleBtn, originalHTML) {
    try {
      if (googleBtn) setGoogleBtnLoading(googleBtn, true);
      showToast('Verifying Google credentials with CyberShield backend...', 'info');

      const data = await apiRequest('/auth/google', 'POST', payload);

      if (data.success && data.token) {
        setToken(data.token);
        setUser(data.user);

        if (googleBtn) {
          googleBtn.innerHTML = '<i class="fas fa-check-circle" style="color:#00c896;"></i> Authentication successful';
          googleBtn.disabled = true;
        }

        showToast('Authentication successful! Redirecting to Dashboard...', 'success');
        setTimeout(() => {
          window.location.href = 'dashboard.html';
        }, 1200);
      } else {
        if (googleBtn) setGoogleBtnLoading(googleBtn, false, originalHTML);
        showToast(data.error || 'Google authentication could not be verified.', 'danger');
      }
    } catch (err) {
      if (googleBtn) setGoogleBtnLoading(googleBtn, false, originalHTML);
      const errMsg = err.message || 'Unable to sign in with Google. Please try again.';
      showToast(errMsg, 'danger');
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

  // Expose global callback helper
  window.handleGoogleCredentialResponse = handleGoogleCredentialResponse;
  window.performGoogleAuthToken = verifyWithBackend;

  document.addEventListener('DOMContentLoaded', initGoogleSSO);
})();
