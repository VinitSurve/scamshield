import { build } from 'vite';
import react from '@vitejs/plugin-react';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';
import fs from 'fs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const rootDir = resolve(__dirname, '..');
const distDir = resolve(rootDir, 'dist');

async function runBuild() {
  console.log('🛡️ Starting ScamShield Chrome Extension Build...');

  // 1. Clean dist directory
  if (fs.existsSync(distDir)) {
    fs.rmSync(distDir, { recursive: true, force: true });
  }
  fs.mkdirSync(distDir, { recursive: true });

  // 2. Build UI HTML Pages (Popup, Options, Interstitial)
  console.log('📦 Building UI Pages (Popup, Options, Interstitial)...');
  await build({
    root: rootDir,
    base: './',
    plugins: [react()],
    build: {
      outDir: distDir,
      emptyOutDir: false,
      rollupOptions: {
        input: {
          popup: resolve(rootDir, 'popup.html'),
          options: resolve(rootDir, 'options.html'),
          interstitial: resolve(rootDir, 'interstitial.html'),
        },
      },
    },
  });

  // 3. Build Background Service Worker (ESM format for MV3 "type": "module")
  console.log('⚙️ Building Background Service Worker...');
  await build({
    root: rootDir,
    build: {
      outDir: distDir,
      emptyOutDir: false,
      lib: {
        entry: resolve(rootDir, 'src/background/service-worker.ts'),
        name: 'BackgroundServiceWorker',
        formats: ['es'],
        fileName: () => 'background.js',
      },
    },
  });

  // 4. Build Content Script (IIFE format for Chrome Isolated World execution)
  console.log('🧩 Building DOM Heuristic Content Script...');
  await build({
    root: rootDir,
    build: {
      outDir: distDir,
      emptyOutDir: false,
      lib: {
        entry: resolve(rootDir, 'src/content/content-script.ts'),
        name: 'ScamShieldContentScript',
        formats: ['iife'],
        fileName: () => 'content.js',
      },
    },
  });

  // 5. Build Gmail Security Content Script (IIFE format)
  console.log('✉️ Building Gmail Guard Content Script...');
  await build({
    root: rootDir,
    build: {
      outDir: distDir,
      emptyOutDir: false,
      lib: {
        entry: resolve(rootDir, 'src/content/gmail.ts'),
        name: 'ScamShieldGmailGuard',
        formats: ['iife'],
        fileName: () => 'gmail.js',
      },
    },
  });

  // 6. Copy Manifest and Icons
  console.log('📋 Copying manifest.json and icons to dist...');
  fs.copyFileSync(resolve(rootDir, 'manifest.json'), resolve(distDir, 'manifest.json'));

  const iconsSrc = resolve(rootDir, 'public/icons');
  const iconsDist = resolve(distDir, 'icons');
  if (fs.existsSync(iconsSrc)) {
    fs.mkdirSync(iconsDist, { recursive: true });
    for (const file of fs.readdirSync(iconsSrc)) {
      fs.copyFileSync(resolve(iconsSrc, file), resolve(iconsDist, file));
    }
  }

  // 7. Validate Build Output
  const requiredFiles = [
    'manifest.json',
    'background.js',
    'content.js',
    'gmail.js',
    'popup.html',
    'options.html',
    'interstitial.html',
    'icons/icon16.png',
    'icons/icon48.png',
    'icons/icon128.png',
  ];

  let missing = [];
  for (const rel of requiredFiles) {
    if (!fs.existsSync(resolve(distDir, rel))) {
      missing.push(rel);
    }
  }

  if (missing.length > 0) {
    console.error('❌ Build failed: Missing required output files:', missing);
    process.exit(1);
  }

  console.log('✅ ScamShield Chrome Extension build completed successfully!');
  console.log(`📁 Unpacked extension ready at: ${distDir}`);
}

runBuild().catch((err) => {
  console.error('Build crashed with error:', err);
  process.exit(1);
});
