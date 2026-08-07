/**
 * CyberShield - Interactive Password Strength Analyzer & Generator
 */

document.addEventListener('DOMContentLoaded', () => {
  const pwdInput = document.getElementById('pwd-analyzer-input');
  const genBtn = document.getElementById('btn-generate-pwd');
  const copyBtn = document.getElementById('btn-copy-pwd');

  if (pwdInput) {
    pwdInput.addEventListener('input', (e) => {
      evaluatePassword(e.target.value);
    });
  }

  if (genBtn) {
    genBtn.addEventListener('click', async () => {
      try {
        const res = await apiRequest('/scan/generate-password');
        if (res.password) {
          if (pwdInput) {
            pwdInput.value = res.password;
            evaluatePassword(res.password);
          }
          showToast('Generated strong cyber-grade password!', 'success');
        }
      } catch (e) {
        // Local generator fallback
        const localPwd = generateLocalPassword(16);
        if (pwdInput) {
          pwdInput.value = localPwd;
          evaluatePassword(localPwd);
        }
        showToast('Generated strong 16-character password', 'success');
      }
    });
  }

  if (copyBtn) {
    copyBtn.addEventListener('click', () => {
      const val = pwdInput ? pwdInput.value : '';
      if (!val) {
        showToast('No password to copy!', 'warning');
        return;
      }
      navigator.clipboard.writeText(val);
      showToast('Password copied to clipboard!', 'success');
    });
  }
});

function evaluatePassword(pwd) {
  if (!pwd) {
    resetMeter();
    return;
  }

  // Client-side entropy & rule analysis
  const len = pwd.length;
  const hasUpper = /[A-Z]/.test(pwd);
  const hasLower = /[a-z]/.test(pwd);
  const hasNum = /[0-9]/.test(pwd);
  const hasSym = /[^A-Za-z0-9]/.test(pwd);

  let pool = 0;
  if (hasUpper) pool += 26;
  if (hasLower) pool += 26;
  if (hasNum) pool += 10;
  if (hasSym) pool += 32;

  let entropy = Math.round(len * Math.log2(pool || 1));
  
  let strength = 'Very Weak';
  let meterWidth = '20%';
  let meterColor = 'var(--neon-red)';

  if (entropy < 28) { strength = 'Very Weak'; meterWidth = '20%'; meterColor = 'var(--neon-red)'; }
  else if (entropy < 45) { strength = 'Weak'; meterWidth = '40%'; meterColor = 'var(--neon-yellow)'; }
  else if (entropy < 65) { strength = 'Medium'; meterWidth = '65%'; meterColor = 'var(--neon-cyan)'; }
  else if (entropy < 85) { strength = 'Strong'; meterWidth = '85%'; meterColor = 'var(--neon-green)'; }
  else { strength = 'Very Strong'; meterWidth = '100%'; meterColor = 'var(--neon-green)'; }

  // Update DOM Elements
  const meterFill = document.getElementById('pwd-meter-fill');
  const labelEl = document.getElementById('pwd-strength-label');
  const entropyEl = document.getElementById('pwd-entropy-value');
  const crackEl = document.getElementById('pwd-crack-time');

  if (meterFill) {
    meterFill.style.width = meterWidth;
    meterFill.style.background = meterColor;
  }
  if (labelEl) {
    labelEl.textContent = strength;
    labelEl.style.color = meterColor;
  }
  if (entropyEl) entropyEl.textContent = `${entropy} bits`;
  if (crackEl) crackEl.textContent = estimateCrackTime(pool, len);

  // Update Checkmarks
  updateCheck('check-length', len >= 12);
  updateCheck('check-upper', hasUpper);
  updateCheck('check-lower', hasLower);
  updateCheck('check-number', hasNum);
  updateCheck('check-symbol', hasSym);
}

function updateCheck(id, pass) {
  const el = document.getElementById(id);
  if (!el) return;
  if (pass) {
    el.className = 'fas fa-check-circle';
    el.style.color = 'var(--neon-green)';
  } else {
    el.className = 'fas fa-times-circle';
    el.style.color = 'var(--text-dim)';
  }
}

function resetMeter() {
  const meterFill = document.getElementById('pwd-meter-fill');
  const labelEl = document.getElementById('pwd-strength-label');
  if (meterFill) meterFill.style.width = '0%';
  if (labelEl) labelEl.textContent = 'None';
  ['check-length', 'check-upper', 'check-lower', 'check-number', 'check-symbol'].forEach(id => updateCheck(id, false));
}

function estimateCrackTime(pool, len) {
  const combs = Math.pow(pool || 1, len);
  const seconds = combs / (2 * 10000000000);
  if (seconds < 1) return '< 1 second';
  if (seconds < 60) return `${Math.round(seconds)} seconds`;
  if (seconds < 3600) return `${Math.round(seconds/60)} minutes`;
  if (seconds < 86400) return `${Math.round(seconds/3600)} hours`;
  if (seconds < 31536000) return `${Math.round(seconds/86400)} days`;
  if (seconds < 3153600000) return `${Math.round(seconds/31536000)} years`;
  return '300+ Trillion Years';
}

function generateLocalPassword(len = 16) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=';
  let pwd = '';
  for (let i = 0; i < len; i++) {
    pwd += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return pwd;
}
