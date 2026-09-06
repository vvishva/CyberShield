/**
 * CyberShield Extension Build & Packaging Pipeline
 * 
 * Generates production builds and store-ready ZIP archives for:
 * 1. Microsoft Edge Add-ons (Manifest V3)
 * 2. Mozilla Firefox Add-ons (Manifest V3 / Gecko)
 * 
 * Usage:
 *   node scripts/build-extensions.js
 */

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const ROOT_DIR = path.resolve(__dirname, '..');
const EXT_SRC = path.join(ROOT_DIR, 'cybershield-extension');
const SHARED_SRC = path.join(EXT_SRC, 'shared');
const BUILDS_DIR = path.join(EXT_SRC, 'builds');
const LOCAL_EXTENSION_DIR = path.join(ROOT_DIR, 'extension');

function cleanDir(dirPath) {
  if (fs.existsSync(dirPath)) {
    fs.rmSync(dirPath, { recursive: true, force: true });
  }
  fs.mkdirSync(dirPath, { recursive: true });
}

function copyRecursive(src, dest) {
  if (!fs.existsSync(src)) return;
  const stats = fs.statSync(src);

  if (stats.isDirectory()) {
    if (!fs.existsSync(dest)) fs.mkdirSync(dest, { recursive: true });
    fs.readdirSync(src).forEach((child) => {
      copyRecursive(path.join(src, child), path.join(dest, child));
    });
  } else {
    fs.copyFileSync(src, dest);
  }
}

function createZipArchive(sourceDir, zipPath) {
  if (fs.existsSync(zipPath)) {
    fs.unlinkSync(zipPath);
  }

  // Windows PowerShell Compress-Archive
  try {
    const cmd = `powershell -NoProfile -Command "Compress-Archive -Path '${path.join(sourceDir, '*')}' -DestinationPath '${zipPath}' -Force"`;
    execSync(cmd, { stdio: 'inherit' });
  } catch (err) {
    console.error(`Failed to create archive ${zipPath}:`, err.message);
    throw err;
  }
}

function validateBuild(buildDir, browserName) {
  console.log(`\nValidating ${browserName} build at ${buildDir}...`);

  // 1. Manifest verification
  const manifestPath = path.join(buildDir, 'manifest.json');
  if (!fs.existsSync(manifestPath)) {
    throw new Error(`[${browserName}] Missing manifest.json`);
  }
  const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));

  // 2. Icon checks
  const requiredIcons = ['16', '32', '48', '128'];
  requiredIcons.forEach((size) => {
    const iconFile = path.join(buildDir, 'icons', `icon${size}.png`);
    if (!fs.existsSync(iconFile)) {
      throw new Error(`[${browserName}] Missing icon: icons/icon${size}.png`);
    }
  });

  // 3. Popup checks
  const popupFiles = ['popup/popup.html', 'popup/popup.js', 'popup/popup.css'];
  popupFiles.forEach((file) => {
    if (!fs.existsSync(path.join(buildDir, file))) {
      throw new Error(`[${browserName}] Missing UI file: ${file}`);
    }
  });

  // 4. Background checks
  const bgFile = path.join(buildDir, 'background', 'background.js');
  if (!fs.existsSync(bgFile)) {
    throw new Error(`[${browserName}] Missing background script: background/background.js`);
  }

  // 5. Shared modules check
  const configPath = path.join(buildDir, 'config', 'config.js');
  if (!fs.existsSync(configPath)) {
    throw new Error(`[${browserName}] Missing config module: config/config.js`);
  }

  // 6. Security scan: verify no localhost strings
  const configContent = fs.readFileSync(configPath, 'utf8');
  if (configContent.includes('localhost') || configContent.includes('127.0.0.1')) {
    throw new Error(`[${browserName}] Security check failed: localhost URL found in production config!`);
  }

  console.log(`✓ ${browserName} build valid (${manifest.name} v${manifest.version})`);
}

function build() {
  console.log('===========================================================');
  console.log('   CYBERSHIELD EXTENSION CROSS-BROWSER PRODUCTION BUILD   ');
  console.log('===========================================================');

  if (!fs.existsSync(SHARED_SRC)) {
    throw new Error(`Shared source directory not found: ${SHARED_SRC}`);
  }

  // Prepare Builds directory
  if (!fs.existsSync(BUILDS_DIR)) {
    fs.mkdirSync(BUILDS_DIR, { recursive: true });
  }

  const edgeBuildDir = path.join(BUILDS_DIR, 'edge');
  const firefoxBuildDir = path.join(BUILDS_DIR, 'firefox');

  cleanDir(edgeBuildDir);
  cleanDir(firefoxBuildDir);

  // ── 1. Build Microsoft Edge Add-on ──────────────────────────────────────────
  console.log('\n[1/4] Compiling Microsoft Edge Add-on build...');
  copyRecursive(SHARED_SRC, edgeBuildDir);
  fs.copyFileSync(
    path.join(EXT_SRC, 'edge', 'manifest.json'),
    path.join(edgeBuildDir, 'manifest.json')
  );
  validateBuild(edgeBuildDir, 'Microsoft Edge');

  // ── 2. Build Mozilla Firefox Add-on ─────────────────────────────────────────
  console.log('\n[2/4] Compiling Mozilla Firefox Add-on build...');
  copyRecursive(SHARED_SRC, firefoxBuildDir);
  fs.copyFileSync(
    path.join(EXT_SRC, 'firefox', 'manifest.json'),
    path.join(firefoxBuildDir, 'manifest.json')
  );
  validateBuild(firefoxBuildDir, 'Mozilla Firefox');

  // ── 3. Package ZIP Archives for Store Submission ────────────────────────────
  console.log('\n[3/4] Packaging Store-ready ZIP bundles...');
  const edgeZip = path.join(BUILDS_DIR, 'CyberShield-Edge.zip');
  const firefoxZip = path.join(BUILDS_DIR, 'CyberShield-Firefox.zip');

  createZipArchive(edgeBuildDir, edgeZip);
  console.log(`✓ Created: ${edgeZip} (${fs.statSync(edgeZip).size} bytes)`);

  createZipArchive(firefoxBuildDir, firefoxZip);
  console.log(`✓ Created: ${firefoxZip} (${fs.statSync(firefoxZip).size} bytes)`);

  // ── 4. Synchronize Root extension/ for Local Unpacked Compatibility ──────────
  console.log('\n[4/4] Synchronizing root extension/ directory for local testing...');
  cleanDir(LOCAL_EXTENSION_DIR);
  copyRecursive(edgeBuildDir, LOCAL_EXTENSION_DIR);
  console.log('✓ Root extension/ directory updated with latest Edge build.');

  console.log('\n===========================================================');
  console.log('   PRODUCTION EXTENSION BUILDS COMPLETED SUCCESSFULLY!    ');
  console.log('===========================================================');
  console.log(`Edge Store Package:    ${edgeZip}`);
  console.log(`Firefox Store Package: ${firefoxZip}`);
  console.log('===========================================================');
}

build();
