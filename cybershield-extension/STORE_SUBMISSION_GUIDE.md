# CyberShield Browser Extension — Production Store Submission & Privacy Guide

This guide provides step-by-step instructions for submitting the CyberShield extension to **Microsoft Edge Add-ons** and **Mozilla Firefox Add-ons (AMO)** completely **free of charge** (no developer registration fees required).

---

## 1. Store Packages Overview

Both production packages have been built and verified in `cybershield-extension/builds/`:

| Store | Package File | Manifest Target | Account Registration Fee |
|---|---|---|---|
| **Microsoft Edge Add-ons** | `CyberShield-Edge.zip` | Manifest V3 (Chromium Service Worker) | **$0 (Free)** |
| **Mozilla Firefox Add-ons** | `CyberShield-Firefox.zip` | Manifest V3 (Gecko Background Scripts) | **$0 (Free)** |

---

## 2. Microsoft Edge Add-ons Submission Guide

Microsoft Edge Add-ons allows developers to publish Chromium extensions without any registration fees.

### Step-by-Step Submission:
1. **Sign in to Microsoft Partner Center:**
   - Go to: [Microsoft Partner Center](https://partner.microsoft.com/en-us/dashboard/microsoftedge/overview)
   - Sign in with your Microsoft account (Personal or Organization).
   - If prompted, complete the free Developer Registration.
2. **Create New Extension:**
   - Click **"Create new extension"**.
   - Drag and drop or upload: `cybershield-extension/builds/CyberShield-Edge.zip`.
3. **Fill in Store Listing Details:**
   - **Name:** `CyberShield AI Security`
   - **Short Description:** `Real-time AI-powered web security monitoring and phishing detection.`
   - **Detailed Description:**
     ```markdown
     CyberShield AI Security protects your web browsing in real time.

     Features:
     - Automatic Threat Detection: Analyzes websites as you browse against phishing, social engineering, and malware databases.
     - Google Safe Browsing Intelligence: Backed by threat intelligence and local heuristic AI engines.
     - Visual Threat Indicators: Instant color-coded safety badges (Safe, Suspicious, Known Threat).
     - Full SOC Scanner Integration: One-click deep security audits for SSL/TLS, security headers, and domain reputation.
     - Privacy-First: Inspects domain names only. Never collects browsing history, search terms, form inputs, or passwords.
     ```
   - **Category:** `Productivity` or `Security`
   - **Website URL:** `https://cybershield-backend-uhwn.onrender.com`
   - **Privacy Policy URL:** `https://cybershield-backend-uhwn.onrender.com/client/privacy.html`
   - **Support Contact:** `support@cybershield.io`
4. **Provide Permission Justifications** (see Section 4 below).
5. **Submit for Review:**
   - Microsoft usually reviews and approves within 24 to 72 hours.

---

## 3. Mozilla Firefox Add-ons (AMO) Submission Guide

Mozilla Firefox Add-ons (addons.mozilla.org) is 100% free for all developers.

### Step-by-Step Submission:
1. **Sign in to AMO Developer Hub:**
   - Go to: [Firefox Add-on Developer Hub](https://addons.mozilla.org/developers/)
   - Sign in or create a Firefox Account (free).
2. **Submit a New Add-on:**
   - Click **"Submit a New Add-on"**.
   - Choose distribution: **"On this site"** (public listing on addons.mozilla.org).
   - Upload: `cybershield-extension/builds/CyberShield-Firefox.zip`.
   - The automated validator will test the manifest and package structure.
3. **Listing Information:**
   - **Name:** `CyberShield AI Security`
   - **Summary:** `Real-time AI-powered web security monitoring and phishing detection.`
   - **Extension ID:** (Already pre-configured in manifest: `cybershield-security@cybershield.io`)
   - **Categories:** `Privacy & Security`
   - **Support Email:** `support@cybershield.io`
   - **Privacy Policy URL:** `https://cybershield-backend-uhwn.onrender.com/client/privacy.html`
4. **Submit for Review:**
   - Automated checks complete immediately. Human review typically takes 1 to 3 days.

---

## 4. Permissions & Justification Declaration

Store submission forms require developers to justify each requested permission. Copy and paste these exact justifications:

| Permission | Why CyberShield Requires It (Copy for Store Reviewers) |
|---|---|
| **`<all_urls>`** (Host Permission) | "Required to inspect the domain hostname of websites visited by the user in real time against threat databases, and to communicate securely with the CyberShield backend API (`https://cybershield-backend-uhwn.onrender.com`)." |
| **`storage`** | "Used strictly to cache domain threat scan results locally for 10 minutes (reducing redundant network requests and conserving user bandwidth) and to store user preferences like pause state." |
| **`alarms`** | "Used to schedule an automatic cache cleanup routine every 30 minutes without running persistent background CPU timers." |
| **`webNavigation`** | "Required to detect top-level navigation events so the security engine can evaluate domain risk before dangerous content is executed." |
| **`tabs`** | "Required to read the active tab URL hostname for domain risk scoring, update the security badge when switching tabs, and open the CyberShield web dashboard when the user clicks 'Run Full Scan'." |
| **`notifications`** | "Used exclusively to issue proactive desktop warning banners to the user when an active phishing or malware domain is detected." |

---

## 5. User Privacy & Data Collection Disclosure

Both Edge and Firefox store forms include a Data Practices / Privacy section. Use this breakdown:

### What CyberShield Collects & Transmits:
- **Domain Name Only:** e.g., `example.com` is transmitted over TLS/HTTPS to the CyberShield backend to query Google Safe Browsing and AI heuristic threat classifiers.
- **Protocol:** Whether the connection is `https:` or `http:`.

### What CyberShield NEVER Collects:
- ❌ **Full URL Paths:** Paths (e.g., `/user/account/12345`) are never transmitted or stored.
- ❌ **Query Parameters:** Query strings, tokens, and search terms are stripped before inspection.
- ❌ **User Data:** Form entries, passwords, keystrokes, cookies, and page HTML are NEVER accessed or stored.
- ❌ **Browsing History:** The extension does not record or profile user browsing history.
- ❌ **Third-Party Trackers:** No analytics trackers or advertising SDKs are bundled.

### Data Retention:
- Cached domain results in browser `storage.local` expire automatically after 10 minutes.
- Audit logs on the backend record anonymous threat verdicts for security analytics and false-positive resolution.
- Users can request deletion of saved alerts at any time via the CyberShield SOC dashboard.

---

## 6. Local Testing Instructions Before Store Submission

### Testing in Microsoft Edge:
1. Open `edge://extensions`.
2. Enable **Developer mode** (bottom-left or top-right toggle).
3. Click **"Load unpacked"** and select:
   `cybershield-extension/builds/edge`
4. Confirm the extension displays *"Allowed on all sites"*.
5. Test a safe site (`https://github.com`) -> Badge turns green `✓`.
6. Test a phishing test URL (`http://testsafebrowsing.appspot.com/s/phishing.html`) -> Badge turns red `✕` and desktop notification fires.

### Testing in Mozilla Firefox:
1. Open `about:debugging#/runtime/this-firefox`.
2. Click **"Load Temporary Add-on..."**.
3. Select `cybershield-extension/builds/firefox/manifest.json`.
4. Verify the extension activates with ID `cybershield-security@cybershield.io`.
5. Test popup, navigation, and recheck features.
