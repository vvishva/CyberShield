/**
 * CyberShield - CyberBot AI Chat Controller
 * Natural-language intent engine with real task execution.
 */

const Scan = require('../models/Scan');
const { predictUrlPhishing } = require('../utils/aiClient');
const { scanWebsiteSecurity } = require('../utils/securityScanner');
const { analyzePassword, generateStrongPassword } = require('../utils/passwordAnalyzer');
const { checkIpReputation } = require('../utils/ipChecker');
const { extractDomainInfo } = require('../utils/domainInfo');

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function pick(...items) {
  return items[Math.floor(Math.random() * items.length)];
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function maskPassword(pwd) {
  if (!pwd) return '';
  if (pwd.length <= 4) return '*'.repeat(pwd.length);
  return pwd.slice(0, 2) + '*'.repeat(pwd.length - 4) + pwd.slice(-2);
}

function extractUrls(text) {
  const urlRegex = /(https?:\/\/[^\s"'<>]+)|(www\.[^\s"'<>]+)|(([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}([\/:][^\s"'<>]*)?)/gi;
  const matches = text.match(urlRegex) || [];
  const cleaned = [];
  for (let m of matches) {
    m = m.replace(/[.,;!?)\]]+$/, '');
    if (/^\d{1,3}(\.\d{1,3}){3}(:\d+)?$/.test(m)) continue; // skip raw IPs
    cleaned.push(m);
  }
  return [...new Set(cleaned)];
}

function extractIp(text) {
  const ipMatch = text.match(/\b((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b/);
  return ipMatch ? ipMatch[0] : null;
}

function extractPassword(text) {
  // Ordered patterns — most specific first. Skip the literal word "password".
  const patterns = [
    /(?:password|pass|pwd)\s*(?:is|:|=)\s*["']?([^\s"']{6,})/i,
    /(?:password|pass|pwd)\s+["']?([^\s"']{6,})/i,
    /(?:check|analyze|strength of|how strong is)\s+(?:the\s+)?(?:password|pass|pwd)?\s*["']?([^\s"']{6,})/i,
    /"([^"]{6,})"/
  ];
  for (const re of patterns) {
    const m = text.match(re);
    if (m && m[1] && !/^password$/i.test(m[1])) {
      return m[1].replace(/[.,;!?)\]]+$/, '');
    }
  }
  return null;
}

function isGreeting(text) {
  return /^(hi|hii+|hello|hey|yo|sup|good\s*(morning|afternoon|evening)|howdy|namaste|hola)\b/i.test(text.trim());
}

function isThanks(text) {
  return /\b(thanks|thank you|thx|ty|appreciate)\b/i.test(text);
}

function isSmallTalk(text) {
  return /\b(how are you|how's it going|what's up|how is it going|good morning|good evening|are you (real|alive|an ai)|can you hear me)\b/i.test(text);
}

function isHelpIntent(text) {
  return /\b(what can you do|help|commands|capabilit|features|how do you work|guide)\b/i.test(text);
}

function isScanIntent(text) {
  return /\b(scan|check|analy|inspect|audit|is\s+.*(safe|secure|legit|phish)|phish|malicious|suspicious|threat)\b/i.test(text);
}

function isPasswordAnalyzeIntent(text) {
  return /\b(password|pass|pwd|password strength|strong password)\b/i.test(text) &&
         /\b(check|analy|strong|weak|strength|entropy|secure|test)\b/i.test(text);
}

function isGeneratePasswordIntent(text) {
  return /\b(generate|make|create|give me|new)\b/i.test(text) &&
         /\b(password|pass|pwd|credential)\b/i.test(text);
}

function isIpIntent(text) {
  return /\b(ip|ip reputation|ip address|blacklist|whois)\b/i.test(text) &&
         /\b(check|scan|analy|look up|reputation|malicious|report)\b/i.test(text);
}

function isRecentScansIntent(text) {
  return /\b(my (recent )?(scans|history|activity)|recent scans|scan history|last scan|show.*scan)\b/i.test(text);
}

function isDnsIntent(text) {
  return /\b(dns|whois|nslookup|resolve|dig)\b/i.test(text);
}

function isJokeIntent(text) {
  return /\b(joke|funny|laugh|humor)\b/i.test(text);
}

// Simple knowledge base for security Q&A
const KNOWLEDGE = [
  {
    keywords: ['what is phishing', 'phishing attack', 'explain phishing'],
    reply: () => '<b>Phishing</b> is a social-engineering attack where a fake website or message imitates a trusted brand to trick you into revealing credentials, payment details, or personal data.<br><br><b>How to spot it:</b> check the exact domain spelling, look for a valid HTTPS padlock, avoid urgent "verify your account" emails, and never reuse passwords. Want me to <b>scan a URL</b> for phishing right now? Just paste it in the chat.'
  },
  {
    keywords: ['what is xss', 'xss attack', 'cross-site scripting'],
    reply: () => '💉 <b>Cross-Site Scripting (XSS)</b> happens when an attacker injects malicious JavaScript into a website that then runs in <i>other users\'</i> browsers. It is used to steal session cookies, hijack accounts, or deface pages.<br><br><b>Defense:</b> a strict <b>Content-Security-Policy</b> header, output encoding/escaping, and input sanitization. This site enforces a CSP in production — you can audit any site\'s headers by telling me to <b>"scan example.com"</b>.'
  },
  {
    keywords: ['what is sql injection', 'sql injection', 'sqli'],
    reply: () => '🗄️ <b>SQL Injection</b> lets an attacker insert malicious SQL into query inputs to read, modify, or delete database records. It is one of the OWASP Top 10 risks.<br><br><b>Defense:</b> use parameterized queries/prepared statements, validate all input, and apply least-privilege DB users.'
  },
  {
    keywords: ['what is hsts', 'hsts header', 'strict transport'],
    reply: () => '🔒 <b>HSTS (Strict-Transport-Security)</b> tells browsers to <i>always</i> connect over HTTPS, preventing protocol-downgrade and cookie-hijacking attacks. Recommended value: <code>max-age=31536000; includeSubDomains; preload</code>. A missing HSTS header is flagged as a MEDIUM severity finding in the CyberShield scanner.'
  },
  {
    keywords: ['what is csp', 'content security policy', 'csp header'],
    reply: () => '🛡️ <b>Content-Security-Policy (CSP)</b> controls which resources a page may load, blocking injected scripts, styles, and iframes — a strong defense against XSS. CyberShield grades sites on CSP presence; want me to check one? Say <b>"scan [domain]"</b>.'
  },
  {
    keywords: ['how to secure', 'improve security', 'best practices'],
    reply: () => 'Here are my top recommendations to raise your security score:<br>1️⃣ Enable <b>HTTPS</b> with a valid TLS certificate<br>2️⃣ Add <b>HSTS</b> + <b>CSP</b> + <b>X-Frame-Options</b> headers<br>3️⃣ Hide the <b>Server</b> banner<br>4️⃣ Add <b>Referrer-Policy</b> and <b>Permissions-Policy</b><br>5️⃣ Use a unique, 16+ char password per account.<br><br>Paste any URL and I\'ll run a live audit for you.'
  },
  {
    keywords: ['what is cybershield', 'about this project', 'what does cybershield do'],
    reply: () => '🚀 <b>CyberShield</b> is a full-stack AI security engine. It provides:<br>🔍 AI-driven <b>phishing detection</b> (Scikit-Learn + heuristic fallback)<br>🛠️ Live <b>website security audits</b> (headers, SSL, vulnerabilities)<br>🔑 <b>Password strength</b> &amp; entropy analysis<br>🌐 <b>IP reputation</b> checks<br>📊 Monitoring, reports &amp; a REST API.<br><br><i>Architect:</i> <b>Vishva</b>. Try me — ask me to scan a URL!'
  },
  {
    keywords: ['who are you', 'your name', 'what are you', 'introduce'],
    reply: () => '🤖 I\'m <b>CyberBot AI</b>, your in-app security advisor — engineered by <b>Vishva</b> for the CyberShield platform. I can analyze URLs for phishing, audit website security headers, check password strength, generate strong passwords, look up IP reputation, and answer security questions. What would you like to check?'
  },
  {
    keywords: ['is cybershield safe', 'is this site secure', 'cybershield security'],
    reply: () => '✅ CyberShield itself runs on a hardened stack: JWT-only auth, helmet security headers, CSP in production, rate limiting, input validation, DB indexes, and its own scanning engine to test third-party sites. Curious about your own site? Tell me to <b>scan [your-domain.com]</b>.'
  },
  {
    keywords: ['what is a strong password', 'strong password', 'good password'],
    reply: () => '🔐 A <b>strong password</b> is 12–16+ characters long, mixes upper/lowercase, numbers, and symbols, avoids dictionary words and repeats, and is <i>unique</i> per account. Rough entropy guide: <b>28–40 bits</b> weak, <b>60–80 bits</b> strong, <b>80+ bits</b> very strong.<br><br>Type <b>"check password Abc!123xyz"</b> and I\'ll score yours, or say <b>"generate password"</b> for a secure random one.'
  },
  {
    keywords: ['mitm', 'man in the middle', 'man-in-the-middle'],
    reply: () => '🎭 <b>Man-in-the-Middle (MitM)</b> attacks intercept traffic between you and the server to steal data. Protection: always use <b>HTTPS</b>, enable <b>HSTS</b>, avoid public Wi-Fi without a VPN, and verify certificate warnings.'
  },
  {
    keywords: ['2fa', 'two factor', 'mfa', 'multi factor'],
    reply: () => '📱 <b>Multi-Factor Authentication</b> adds a second proof of identity (OTP, authenticator app, or hardware key) beyond your password. It blocks ~99% of automated account-takeover attacks. Enable it everywhere sensitive, especially email and banking.'
  },
  {
    keywords: ['how to report phishing', 'report phishing', 'report suspicious'],
    reply: () => '🚩 To report a phishing site: submit it to <b>Google Safe Browsing</b> (safe browsing.google.com/report_phishing), <b>PhishTank</b>, and your email provider. In CyberShield, any URL I flag as phishing will include these steps in its recommendations.'
  }
];

function knowledgeAnswer(text) {
  const lower = text.toLowerCase();
  for (const entry of KNOWLEDGE) {
    if (entry.keywords.some(k => lower.includes(k))) {
      return entry.reply();
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// Task runners (return HTML reply + optional structured payload)
// ---------------------------------------------------------------------------

async function runUrlScan(message, url) {
  // Prefer the comprehensive website audit when the user asks to "audit",
  // otherwise use the phishing classifier.
  if (/\b(audit|security audit|headers|ssl|vulnerab)\b/i.test(message)) {
    const result = await scanWebsiteSecurity(url);
    if (result.ssrfBlocked) {
      return {
        reply: `⛔ <b>Scan blocked.</b> ${escapeHtml(result.error || 'That host is not permitted.')} I can only audit public, internet-facing websites.`,
        data: { type: 'scan', blocked: true }
      };
    }
    if (!result.domain) {
      return {
        reply: `⚠️ I couldn't parse <b>${escapeHtml(url)}</b> as a valid URL. Please send a full link like <code>https://example.com</code>.`,
        data: { type: 'scan', error: 'invalid url' }
      };
    }
    const vulnCount = result.vulnerabilities.length;
    const headerLine = result.missingHeaders.length
      ? `<b>Missing headers:</b> ${result.missingHeaders.map(escapeHtml).join(', ')}`
      : '✅ <b>All key security headers present!</b>';
    const topVulns = result.vulnerabilities.slice(0, 4).map(v =>
      `<li><b>[${escapeHtml(v.severity)}]</b> ${escapeHtml(v.title)}</li>`
    ).join('');

    return {
      reply: `🛠️ <b>Website Security Audit — ${escapeHtml(result.domain)}</b><br>` +
        `Score: <b>${result.securityScore}/100</b> (${escapeHtml(result.riskLevel)}) · HTTPS: ${result.hasHttps ? '✅' : '❌'} · Duration: ${result.scanDuration}ms<br>` +
        `${headerLine}<br>` +
        (topVulns ? `<b>Findings (${vulnCount}):</b><ul style="margin:4px 0 0 18px;">${topVulns}</ul>` : '<b>No critical findings.</b>') +
        '<br>Full details are saved under the <b>Reports</b> tab.',
      data: { type: 'scan', result }
    };
  }

  const result = await predictUrlPhishing(url);
  const icon = result.status === 'Phishing' ? '🚨' : result.status === 'Suspicious' ? '⚠️' : '✅';
  const recs = (result.recommendations || []).slice(0, 3).map(r =>
    `<li>${escapeHtml(r)}</li>`
  ).join('');

  return {
    reply: `${icon} <b>Phishing Analysis — ${escapeHtml(url)}</b><br>` +
      `Verdict: <b>${escapeHtml(result.status)}</b> · Risk: ${result.riskPercentage}/100 · Confidence: ${result.confidenceScore}%<br>` +
      `Model: <i>${escapeHtml(result.modelUsed || 'heuristic engine')}</i>` +
      (recs ? `<br><b>Recommendations:</b><ul style="margin:4px 0 0 18px;">${recs}</ul>` : ''),
    data: { type: 'scan', result }
  };
}

function runPasswordCheck(password) {
  const result = analyzePassword(password);
  const icons = { 'Very Weak': '🔴', 'Weak': '🟠', 'Medium': '🟡', 'Strong': '🟢', 'Very Strong': '🟢' };
  const icon = icons[result.strength] || '❓';
  const checks = [
    ['Length ≥ 12', result.checks.length],
    ['Uppercase', result.checks.hasUppercase],
    ['Lowercase', result.checks.hasLowercase],
    ['Numbers', result.checks.hasNumbers],
    ['Symbols', result.checks.hasSymbols]
  ].map(([label, ok]) => `${ok ? '✅' : '❌'} ${label}`).join(' · ');

  const suggestions = (result.suggestions || []).slice(0, 4).map(s =>
    `<li>${escapeHtml(s)}</li>`
  ).join('');

  return {
    reply: `${icon} <b>Password Strength: ${escapeHtml(result.strength)}</b><br>` +
      `Entropy: <b>${result.entropyBits} bits</b> · Est. crack time: <b>${escapeHtml(result.timeToCrack)}</b><br>` +
      `${checks}<br>` +
      (suggestions ? `<b>Tips:</b><ul style="margin:4px 0 0 18px;">${suggestions}</ul>` : '<b>Great password — keep it unique!</b>'),
    data: { type: 'password', result }
  };
}

function runIpCheck(ip) {
  const result = checkIpReputation(ip);
  const icon = result.riskLevel === 'Safe' ? '✅' : result.riskLevel === 'Medium Risk' ? '⚠️' : '🚨';
  const details = (result.details || []).slice(0, 4).map(d => `<li>${escapeHtml(d)}</li>`).join('');
  return {
    reply: `${icon} <b>IP Reputation — ${escapeHtml(result.ip)}</b><br>` +
      `Risk: <b>${escapeHtml(result.riskLevel)}</b> · Threat Score: ${result.threatScore}/100 · Blacklist: ${escapeHtml(result.blacklistStatus)}<br>` +
      `Location: ${escapeHtml(result.country)} · ISP: ${escapeHtml(result.isp)}<br>` +
      `<ul style="margin:4px 0 0 18px;">${details}</ul>`,
    data: { type: 'ip', result }
  };
}

function runPasswordGenerate() {
  const pwd = generateStrongPassword(16);
  return {
    reply: `🎲 Here is a cryptographically-strong random password (<b>${pwd.length}</b> chars, entropy ≈ 106 bits):<br><code style="background:#111;padding:4px 8px;border-radius:4px;display:inline-block;margin:6px 0;">${escapeHtml(pwd)}</code><br>Store it in a password manager — never share it in chat. Type <b>"check password ..."</b> if you want me to test a password's strength.`,
    data: { type: 'generate_password', password: pwd }
  };
}

async function runRecentScans(userId) {
  if (!userId) {
    return {
      reply: '📋 To show your scan history I need you to be signed in. Once logged in, ask me <b>"show my recent scans"</b> again.',
      data: { type: 'recent_scans', empty: true }
    };
  }
  const scans = await Scan.find({ user: userId }).sort({ createdAt: -1 }).limit(5);
  if (scans.length === 0) {
    return {
      reply: '📋 You don\'t have any scans yet. Run one by asking me to <b>scan a URL</b>, or use the Scanner page, then I\'ll summarize it here.',
      data: { type: 'recent_scans', empty: true }
    };
  }
  const rows = scans.map(s => {
    const icon = s.status === 'Safe' || s.status === 'Strong' ? '✅' : s.status === 'Suspicious' || s.status === 'Medium Risk' ? '⚠️' : '🚨';
    return `<li>${icon} <b>${escapeHtml(s.target)}</b> — ${escapeHtml(s.status)} (${s.riskScore}/100) · ${s.scanType.replace(/_/g, ' ')}</li>`;
  }).join('');
  return {
    reply: `📊 <b>Your ${scans.length} most recent scans:</b><ul style="margin:4px 0 0 18px;">${rows}</ul>`,
    data: { type: 'recent_scans', count: scans.length, scans }
  };
}

const dnsPromises = require('dns').promises;

async function runDnsLookup(domain) {
  try {
    const cleanDomain = domain.replace(/^https?:\/\//, '').replace(/\/.*$/, '');
    const records = await dnsPromises.resolveAny(cleanDomain);
    const formatted = records.map(r => {
      if (r.type === 'A' || r.type === 'AAAA') return `<li><b>${r.type}</b>: ${r.address}</li>`;
      if (r.type === 'MX') return `<li><b>MX</b>: ${r.exchange} (priority: ${r.priority})</li>`;
      if (r.type === 'TXT') return `<li><b>TXT</b>: ${r.entries.join(' ')}</li>`;
      if (r.type === 'NS') return `<li><b>NS</b>: ${r.value}</li>`;
      if (r.type === 'CNAME') return `<li><b>CNAME</b>: ${r.value}</li>`;
      return `<li><b>${r.type}</b></li>`;
    }).join('');
    
    return {
      reply: `🔍 <b>DNS Records for ${escapeHtml(cleanDomain)}</b><ul style="margin:4px 0 0 18px;">${formatted || '<li>No standard records found.</li>'}</ul>`,
      data: { type: 'dns', domain: cleanDomain, records }
    };
  } catch (err) {
    return {
      reply: `⚠️ Failed to resolve DNS for <b>${escapeHtml(domain)}</b>: ${escapeHtml(err.message)}`,
      data: { type: 'dns', error: err.message }
    };
  }
}

function runJoke() {
  const jokes = [
    "Why did the web developer leave the restaurant? Because of the cross-site scripting!",
    "A SQL query goes into a bar, walks up to two tables and asks: 'Can I join you?'",
    "Why do programmers prefer dark mode? Because light attracts bugs!",
    "How many programmers does it take to change a light bulb? None, that's a hardware problem.",
    "There are 10 types of people in the world: those who understand binary, and those who don't."
  ];
  return {
    reply: `😄 ${pick(...jokes)}`,
    data: { type: 'joke' }
  };
}

// ---------------------------------------------------------------------------
// Intent Router
// ---------------------------------------------------------------------------

exports.processChat = async (req, res) => {
  try {
    const { message } = req.body;
    if (!message || !String(message).trim()) {
      return res.status(400).json({ success: false, error: 'Please send me a message to work with.' });
    }

    const text = String(message).trim();
    const userId = req.user ? req.user._id : null;
    let reply = '';
    let data = null;

    // 1. Greetings / pleasantries
    if (isGreeting(text)) {
      reply = pick(
        `👋 Hello${userId ? `, ${escapeHtml((req.user.username || 'friend').split(' ')[0])}` : ''}! I'm CyberBot AI. Ask me to <b>scan a URL</b>, <b>check a password</b>, <b>look up an IP</b>, or just answer a security question. What can I help you with today?`,
        'Hey there! 👋 Ready when you are — paste a <b>suspicious URL</b>, type a <b>password</b> to test, or ask me anything about web security.'
      );
    } else if (isThanks(text)) {
      reply = pick('You\'re welcome! 🛡️ Stay safe out there — ping me anytime.', 'Anytime! If you have another URL or password to check, just send it over.');
    } else if (isSmallTalk(text)) {
      reply = pick(
        'Running at 100% ⚡ All shields up — AI models loaded, scanning engine online. I\'m here to protect your sessions. What would you like to check?',
        'I\'m great, thanks for asking! 🤖 Just finished booting my security engines. Feed me a URL or a password and I\'ll put them to work.',
        'All systems nominal ✅ — as a good bot should be. Now, let\'s get to work: scan a URL, test a password, or check an IP?'
      );
    } else if (isHelpIntent(text)) {
      reply = '🧠 <b>Here\'s what I can do for you:</b><br>' +
        '🔍 <b>Scan a URL</b> — "is https://example.com safe?"<br>' +
        '🛠️ <b>Full website audit</b> — "audit example.com"<br>' +
        '🔑 <b>Password strength</b> — "check password Abc!123xyz"<br>' +
        '🎲 <b>Generate password</b> — "generate a strong password"<br>' +
        '🌐 <b>IP reputation</b> — "check IP 8.8.8.8"<br>' +
        '📋 <b>Scan history</b> — "show my recent scans"<br>' +
        '💡 <b>Security Q&A</b> — "what is phishing?" / "what is XSS?"<br><br>Try one now!';
    } else {
      // 2. Task: password generation
      if (isGeneratePasswordIntent(text)) {
        const run = runPasswordGenerate();
        reply = run.reply;
        data = run.data;
      }
      // 3. Task: password analysis (needs an inline password)
      else if (isPasswordAnalyzeIntent(text) && extractPassword(text)) {
        const pwd = extractPassword(text);
        const run = runPasswordCheck(pwd);
        reply = run.reply;
        data = run.data;
      }
      // 4. Task: IP check
      else if (isIpIntent(text) && extractIp(text)) {
        const run = runIpCheck(extractIp(text));
        reply = run.reply;
        data = run.data;
      }
      // 5. Task: recent scans
      else if (isRecentScansIntent(text)) {
        const run = await runRecentScans(userId);
        reply = run.reply;
        data = run.data;
      }
      // 6. Task: URL scanning / phishing
      else if (isScanIntent(text) || extractUrls(text).length > 0) {
        const urls = extractUrls(text);
        if (urls.length === 0) {
          reply = '🤔 I\'d love to scan something for you, but I couldn\'t find a URL in your message. Try: <b>"is https://example.com safe?"</b>';
        } else {
          // If user specifically asked for DNS
          if (isDnsIntent(text)) {
            const run = await runDnsLookup(urls[0]);
            reply = run.reply;
            data = run.data;
          } else {
            const run = await runUrlScan(text, urls[0]);
            reply = run.reply;
            data = run.data;
          }
        }
      }
      // 7. DNS Lookup specifically
      else if (isDnsIntent(text) && extractUrls(text).length > 0) {
         const run = await runDnsLookup(extractUrls(text)[0]);
         reply = run.reply;
         data = run.data;
      }
      // 8. Joke
      else if (isJokeIntent(text)) {
         const run = runJoke();
         reply = run.reply;
         data = run.data;
      }
      // 7. Knowledge base Q&A
      else {
        const kb = knowledgeAnswer(text);
        if (kb) {
          reply = kb;
        } else {
          // 8. Natural fallback
          reply = pick(
            `Hmm, I'm not 100% sure what you mean by <i>${escapeHtml(text.length > 40 ? text.slice(0, 40) + '…' : text)}</i>. I'm best at <b>scanning URLs</b>, <b>auditing websites</b>, <b>testing passwords</b>, <b>checking IPs</b>, and answering <b>security questions</b>. Try "what can you do?"`,
            'I don\'t have a confident answer for that yet — my specialty is cybersecurity. Try asking me to <b>scan a URL</b>, <b>check a password</b>, or ask <b>"what is phishing?"</b>',
            'That\'s outside my core knowledge, but I\'m always learning! 👨‍💻 For anything web-security related — URL scans, password strength, IP checks, header audits — I\'m your bot. Say <b>"help"</b> to see my commands.'
          );
        }
      }
    }

    res.status(200).json({ success: true, reply, data });
  } catch (err) {
    console.error('[CyberBot] Chat error:', err.message);
    res.status(500).json({
      success: false,
      error: 'CyberBot hit an unexpected error. Please try again.',
      reply: `😓 I ran into an error while processing that (${escapeHtml(err.message)}). Give it another try, or ask me <b>"help"</b>.`
    });
  }
};
