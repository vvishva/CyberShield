/**
 * CyberShield AI — Password Analyzer Logic
 * 100% Client-Side implementation.
 */

document.addEventListener('DOMContentLoaded', () => {
  const pwdInput = document.getElementById('pwd-input');
  const toggleVis = document.getElementById('toggle-pwd-vis');
  
  const bar = document.getElementById('pwd-strength-bar');
  const scoreText = document.getElementById('pwd-score-text');
  const verdict = document.getElementById('pwd-verdict');
  const crackTimeEl = document.getElementById('crack-time');
  
  const critElements = {
    length: document.getElementById('crit-length'),
    upper: document.getElementById('crit-upper'),
    lower: document.getElementById('crit-lower'),
    num: document.getElementById('crit-num'),
    sym: document.getElementById('crit-sym')
  };

  // Toggle Visibility
  if (toggleVis && pwdInput) {
    toggleVis.addEventListener('click', () => {
      if (pwdInput.type === 'password') {
        pwdInput.type = 'text';
        toggleVis.className = 'fas fa-eye-slash';
      } else {
        pwdInput.type = 'password';
        toggleVis.className = 'fas fa-eye';
      }
    });
  }

  // Analyze Password
  if (pwdInput) {
    pwdInput.addEventListener('input', (e) => {
      const pwd = e.target.value;
      analyze(pwd);
    });
  }

  function analyze(pwd) {
    if (!pwd) {
      resetUI();
      return;
    }

    let score = 0;
    
    const criteria = {
      length: pwd.length >= 12,
      upper: /[A-Z]/.test(pwd),
      lower: /[a-z]/.test(pwd),
      num: /[0-9]/.test(pwd),
      sym: /[^A-Za-z0-9]/.test(pwd)
    };

    // Score calculation
    if (pwd.length > 0) score += Math.min(pwd.length * 3, 30);
    if (criteria.upper) score += 15;
    if (criteria.lower) score += 15;
    if (criteria.num) score += 15;
    if (criteria.sym) score += 25;

    // Penalty for repeats
    if (/(.)\1{2,}/.test(pwd)) score -= 15; // e.g. aaa
    if (/^[a-zA-Z]+$/.test(pwd) && pwd.length < 12) score -= 10; // only letters
    
    score = Math.max(0, Math.min(100, Math.round(score)));

    // Update UI
    bar.style.width = score + '%';
    scoreText.textContent = score + '/100';

    let color = 'var(--neon-red)';
    let vText = 'Very Weak';
    let vClass = 'badge-danger';
    
    if (score >= 80) { color = 'var(--neon-green)'; vText = 'Strong'; vClass = 'badge-safe'; }
    else if (score >= 60) { color = 'var(--neon-cyan)'; vText = 'Good'; vClass = 'badge-info'; }
    else if (score >= 40) { color = 'var(--neon-amber)'; vText = 'Fair'; vClass = 'badge-warning'; }
    
    bar.style.backgroundColor = color;
    scoreText.style.color = color;
    verdict.textContent = vText;
    verdict.className = 'badge ' + vClass;

    // Update criteria list
    updateCrit(critElements.length, criteria.length);
    updateCrit(critElements.upper, criteria.upper);
    updateCrit(critElements.lower, criteria.lower);
    updateCrit(critElements.num, criteria.num);
    updateCrit(critElements.sym, criteria.sym);

    // Calculate entropy & crack time (rough estimation for UI)
    let poolSize = 0;
    if (criteria.lower) poolSize += 26;
    if (criteria.upper) poolSize += 26;
    if (criteria.num) poolSize += 10;
    if (criteria.sym) poolSize += 32;
    
    if (poolSize === 0) { crackTimeEl.textContent = 'Instant'; return; }
    
    const entropy = pwd.length * Math.log2(poolSize);
    
    // Assume 100 billion guesses per second (modern botnet)
    const guessesPerSec = 100000000000;
    const combinations = Math.pow(poolSize, pwd.length);
    const seconds = combinations / guessesPerSec;
    
    crackTimeEl.textContent = formatTime(seconds);
    crackTimeEl.style.color = color;
  }

  function updateCrit(el, passed) {
    if (!el) return;
    if (passed) {
      el.style.color = '#fff';
      el.innerHTML = `<i class="fas fa-check-circle" style="color:var(--neon-green); width:20px;"></i> ` + el.textContent.trim();
    } else {
      el.style.color = 'var(--text-muted)';
      el.innerHTML = `<i class="fas fa-times-circle" style="color:var(--neon-red); width:20px;"></i> ` + el.textContent.trim();
    }
  }

  function resetUI() {
    bar.style.width = '0%';
    scoreText.textContent = '0/100';
    scoreText.style.color = 'var(--neon-red)';
    verdict.textContent = 'Very Weak';
    verdict.className = 'badge badge-danger';
    crackTimeEl.textContent = 'Instant';
    crackTimeEl.style.color = '#fff';
    Object.values(critElements).forEach(el => updateCrit(el, false));
  }

  function formatTime(seconds) {
    if (seconds < 1) return 'Instant';
    if (seconds < 60) return Math.round(seconds) + ' seconds';
    if (seconds < 3600) return Math.round(seconds / 60) + ' minutes';
    if (seconds < 86400) return Math.round(seconds / 3600) + ' hours';
    if (seconds < 31536000) return Math.round(seconds / 86400) + ' days';
    if (seconds < 3153600000) return Math.round(seconds / 31536000) + ' years';
    return 'Centuries';
  }

  // Password Generator
  const genBtn = document.getElementById('generate-btn');
  const genInput = document.getElementById('generated-pwd');
  const copyBtn = document.getElementById('copy-pwd-btn');
  const lenRange = document.getElementById('gen-length');
  const lenVal = document.getElementById('gen-length-val');

  if (lenRange) {
    lenRange.addEventListener('input', (e) => {
      lenVal.textContent = e.target.value;
    });
  }

  if (genBtn) {
    genBtn.addEventListener('click', () => {
      const length = parseInt(lenRange.value, 10);
      const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+~`|}{[]:;?><,./-=';
      let retVal = '';
      const randomValues = new Uint32Array(length);
      window.crypto.getRandomValues(randomValues);
      for (let i = 0; i < length; i++) {
        retVal += charset[randomValues[i] % charset.length];
      }
      genInput.value = retVal;
      
      // Auto-analyze generated password
      pwdInput.value = retVal;
      analyze(retVal);
    });
  }

  if (copyBtn) {
    copyBtn.addEventListener('click', () => {
      if (!genInput.value) return;
      navigator.clipboard.writeText(genInput.value).then(() => {
        const icon = copyBtn.querySelector('i');
        icon.className = 'fas fa-check';
        setTimeout(() => icon.className = 'fas fa-copy', 2000);
      });
    });
  }
});
