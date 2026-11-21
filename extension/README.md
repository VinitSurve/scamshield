# ScamShield Browser Security Extension (Manifest V3)

> **Think Before You Click.**  
> Real-time, privacy-preserving threat intelligence and scam protection for Chromium browsers.

[![Manifest](https://img.shields.io/badge/manifest-v3-orange.svg)](manifest.json)
[![TypeScript](https://img.shields.io/badge/language-TypeScript-blue.svg)](tsconfig.json)
[![Tests](https://img.shields.io/badge/tests-39%20passed-brightgreen.svg)](tests/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](../LICENSE)

---

## 1. Overview & Vision

**ScamShield** protects ordinary users against financial fraud, credential harvesting, fake KYC updates, deceptive redirect funnels, and brand impersonation. Built specifically with the Indian cyber threat landscape in mind, the extension detects threats impersonating Indian financial and public services (SBI, HDFC, ICICI, PayTM, Parivahan eChallan, MSEDCL Electricity) while upholding strict zero-telemetry user privacy.

---

## 2. Key Features Implemented

- **Proactive Navigation Gating:** Evaluates destinations in `chrome.webNavigation.onBeforeNavigate` and immediately halts navigation to verified phishing portals, redirecting to an internal educational warning interstitial.
- **Kernel-Level Declarative Blocking (DNR):** Synchronizes high-confidence malicious domains into Chrome's `declarativeNetRequest` dynamic rules for microsecond offline enforcement.
- **Privacy-Preserving k-Anonymity Lookups:** Uses 32-bit SHA-256 domain prefix hashes (`/api/v1/reputation/prefix/{prefix}`). The remote backend never learns which domain or URL the user is visiting.
- **Multi-Hop Deceptive Redirect Tracker:** Records navigation hops across origin boundaries to detect short links bouncing through ad trackers into malicious landing domains.
- **Brand Impersonation & Homoglyph Heuristics:** Detects Punycode (`xn--`) attacks and confusable Cyrillic/Greek characters, as well as brand keyword hijacking across non-official domains.
- **Protected Tranco Anchors:** Top-ranked global websites (Tranco Top 100K list) are permanently immune to false-positive blocks and brigade poisoning.
- **Passive DOM Heuristic Scanner:** Identifies password and payment fields on unverified domains without attaching keylisteners or capturing user input.
- **Gmail Web Email Guard:** Scoped to `mail.google.com`, compares sender display names against actual SMTP envelopes to inject security safety pills.
- **One-Click Community Reporting:** Allows instant submission of phishing domains from the popup, queuing reports locally when offline.
- **Educational Warning Interstitial:** Explains the specific evidence behind a block with a safe "Back to Safety" default and a deliberate override option.
- **Multilingual Support (India-Focused):** Native support for English, Hindi (हिन्दी), and Marathi (मराठी).

---

## 3. Architecture & Directory Layout

```
extension/
├── manifest.json              # Chrome Manifest V3 declaration
├── package.json               # Scripts and dependencies
├── tsconfig.json              # Strict TypeScript compiler options
├── vite.config.ts             # Vitest test configuration
├── tailwind.config.js         # Cyber design system tokens
├── popup.html                 # Extension Popup Entry
├── options.html               # Settings / Options Entry
├── interstitial.html          # Warning Interstitial Entry
├── dist/                      # Compiled, unpacked extension ready for Chrome
├── scripts/
│   └── build.js               # Multi-target Vite build runner
├── src/
│   ├── background/
│   │   ├── service-worker.ts     # Ephemeral MV3 service worker bootstrap
│   │   ├── navigation-monitor.ts # Navigation interception & badge manager
│   │   ├── redirect-tracker.ts   # Multi-hop redirect chain tracer
│   │   └── dnr-manager.ts        # DeclarativeNetRequest dynamic rules
│   ├── content/
│   │   ├── content-script.ts     # Passive DOM heuristics (zero keystrokes)
│   │   └── gmail.ts              # Scoped Gmail web impersonation guard
│   ├── popup/
│   │   ├── PopupApp.tsx          # Main React popup dashboard
│   │   └── components/           # Header, StatusCard, QuickActions, ReportModal
│   ├── options/
│   │   └── OptionsApp.tsx        # Settings, whitelist, language, cache controls
│   ├── interstitial/
│   │   └── InterstitialApp.tsx   # Warning screen with deliberate override
│   ├── security/
│   │   ├── url-validator.ts      # Canonicalization, SSRF & loopback checks
│   │   ├── domain-normalizer.ts  # TLD extraction, homoglyphs, brand registry
│   │   └── safe-messaging.ts     # Runtime message sender/origin validator
│   ├── services/
│   │   ├── api-client.ts         # REST API client with timeout & retry
│   │   ├── reputation-service.ts # 7-step master evaluation pipeline
│   │   └── report-service.ts     # Community threat report submission
│   ├── storage/
│   │   ├── cache-service.ts      # L1/L2 cache & offline threat intelligence
│   │   └── settings-service.ts   # Persistent user preferences & whitelists
│   ├── i18n/
│   │   ├── index.ts              # Locale resolver
│   │   ├── en.ts                 # English
│   │   ├── hi.ts                 # Hindi
│   │   └── mr.ts                 # Marathi
│   └── utils/
│       ├── crypto.ts             # Web Crypto SHA-256 & 32-bit prefix helper
│       └── logger.ts             # Privacy-safe, redacted logger
└── tests/
    ├── setup.ts                  # Chrome API & fetch mocks
    ├── url-validator.test.ts     # Canonicalization & SSRF tests
    ├── domain-normalizer.test.ts # Homoglyph & brand impersonation tests
    ├── crypto.test.ts            # Hash & prefix calculation tests
    ├── cache-service.test.ts     # Tranco & offline threat cache tests
    ├── reputation-service.test.ts# Master evaluation pipeline tests
    ├── redirect-tracker.test.ts  # Multi-hop & loop detection tests
    ├── api-client.test.ts        # k-Anonymity & reporting integration tests
    ├── safe-messaging.test.ts    # Sender verification tests
    └── i18n.test.ts              # Localization tests
```

---

## 4. Manifest V3 Permissions Explained

ScamShield strictly adheres to the principle of least privilege:

| Permission | Justification |
| :--- | :--- |
| `storage` | Required to persist user settings, whitelisted domains, and local threat cache in `chrome.storage.local`. |
| `webNavigation` | Required to intercept `onBeforeNavigate` for proactive malicious domain blocking and redirect tracing. |
| `alarms` | Required to schedule periodic threat intelligence delta synchronizations. |
| `declarativeNetRequest` | Required for instant kernel-level redirection of known critical phishing domains to the interstitial. |
| `host_permissions` (`http://*/*`, `https://*/*`) | Required for navigation monitoring across public internet domains. |

**Permissions Explicitly Eliminated:**
- ❌ `cookies`: Never requested; zero cookie tracking.
- ❌ `history`: Never requested; full browsing history is never traversed.
- ❌ `<all_urls>` script injection: Content scripts are scoped or passive.

---

## 5. Development & Build Instructions

### Prerequisites
- **Node.js:** v20+ (tested on Node v24.21.0)
- **Package Manager:** npm

### Setup
```bash
# Navigate to the extension directory
cd extension

# Install dependencies
npm install

# Run TypeScript typecheck
npm run typecheck

# Run test suite (Vitest)
npm run test

# Compile production build
npm run build
```

The compiled, loadable extension is emitted into the `extension/dist/` directory.

---

## 6. How to Load in Google Chrome / Chromium

1. Open **Google Chrome** (or Chromium / Brave / Edge).
2. Navigate to `chrome://extensions/` in the address bar.
3. Enable **Developer mode** toggle in the top-right corner.
4. Click the **Load unpacked** button in the top-left toolbar.
5. In the file picker, select the `extension/dist` folder (NOT the root `extension` folder).
6. ScamShield will now appear in your browser extensions toolbar! Click the puzzle icon and pin ScamShield for instant access.

---

## 7. Security Test Lab [Developer / Hackathon Suite]

ScamShield includes a dedicated, developer-accessible **Security Test Lab** to evaluate website detection, risk scoring, Tranco trust anchors, brand-impersonation heuristics, and redirect chain monitoring in a safe, controlled environment.

### How to Access the Test Lab
1. Click the ScamShield extension icon in the Chrome toolbar.
2. Click **"Security Test Lab [Dev Mode]"** at the bottom of the popup (or open `chrome-extension://<id>/test-lab.html` directly in a new tab).
3. Click **"Run All Tests"** to execute the diagnostic suite sequentially with live progress tracking, or run individual tests on demand.

### Test Matrix (10 Controlled Scenarios)
| Test Case | Target URL | Expected Category | Expected Severity | Detection Mechanism |
| :--- | :--- | :--- | :--- | :--- |
| **Legitimate Google** | `https://google.com` | `LEGITIMATE` | `SAFE` | Tranco Protected Anchor List |
| **Legitimate GitHub** | `https://github.com` | `LEGITIMATE` | `SAFE` | Tranco Protected Anchor List |
| **Legitimate Microsoft** | `https://microsoft.com` | `LEGITIMATE` | `SAFE` | Tranco Protected Anchor List |
| **Legitimate Amazon India** | `https://amazon.in` | `LEGITIMATE` | `SAFE` | Tranco Protected Anchor List |
| **SBI Impersonation** | `https://sbi-online-kyc-verification.example` | `PHISHING` | `CRITICAL` / `HIGH` | Heuristic Brand Impersonation Registry |
| **HDFC Impersonation** | `https://hdfc-bank-secure-login.example` | `PHISHING` | `CRITICAL` / `HIGH` | Heuristic Brand Impersonation Registry |
| **PhonePe Impersonation** | `https://phonepe-account-verify.example` | `PHISHING` | `CRITICAL` / `HIGH` | Heuristic Brand Impersonation Registry |
| **Known Threat Fixture** | `https://sbi-online-kyc-verification.top` | `FAKE_KYC` | `CRITICAL` | High-Confidence Offline Threat DB |
| **Deceptive Redirect Chain** | `shortener.example -> tracker.example -> sbi-online-kyc-verification.top` | `FAKE_KYC` | `CRITICAL` / `HIGH` | Multi-Hop Redirect Tracker |
| **Input Safety Fixture** | `not a valid url %%%` | `LEGITIMATE` / `UNKNOWN` | `SAFE` / `UNKNOWN` | Canonicalizer Exception Handling |

---

## 8. Manual Verification & Test URLs

To safely verify ScamShield's protection mechanisms without visiting dangerous live malware:

| Test Destination | Scenario | Expected Behavior |
| :--- | :--- | :--- |
| `https://sbi-online-kyc-verification.top` | Known Fake KYC Lure | **BLOCKED:** Immediate redirect to ScamShield Interstitial warning. |
| `https://fake-challan-pay.online` | Fake Traffic Challan Lure | **BLOCKED:** Immediate redirect to ScamShield Interstitial warning. |
| `https://electricity-bill-update.xyz` | MSEDCL Bill Scam | **BLOCKED:** Immediate redirect to ScamShield Interstitial warning. |
| `https://onlinesbi.sbi` | Legitimate Official Bank | **PASS:** Instant pass with green shield badge (`✓`). |
| `https://google.com` | Tranco Protected Anchor | **PASS:** Instant pass; zero latency. |
| `https://xn--80ak6aa92e.com` | Punycode Homoglyph | **WARNING:** Popup flags suspicious homoglyph attack. |
| `http://127.0.0.1:8080` | Private Loopback Host | **PASS:** Local developer addresses treated as safe. |

---

## 8. Real Mode vs. Developer Demo Mode

- **Real Mode (Default):** Queries the ScamShield backend API gateway using 32-bit k-anonymity prefix hashes. If the backend is unreachable or offline, the extension seamlessly falls back to its local high-confidence threat dataset and heuristic engine without falsely declaring unknown sites safe.
- **Developer Demo Mode:** Configurable in Extension Settings. Generates labeled synthetic threat fixtures (e.g., domains containing `demo-phish` or `test-scam`) for demonstrations when disconnected from backend infrastructure.

---

## 9. Known Limitations

1. **Pre-Request Synchronous API Latency:** In Manifest V3, extensions cannot synchronously stall network requests while awaiting a multi-second remote API response without blocking APIs. We solve this by using pre-compiled DNR rules and instant local cache checks, with asynchronous redirect to interstitial if flagged during navigation.
2. **Service Worker Termination:** Manifest V3 service workers sleep after ~30 seconds of inactivity. All state is maintained in `chrome.storage.local` and memory caches are re-hydrated on activation.
3. **Gmail Web Interface Changes:** The Gmail email scanner relies on standard Gmail DOM selectors (`span.gD`, `span[email]`). Major layout changes by Google may require periodic selector updates.
