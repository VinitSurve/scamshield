# ScamShield — Engineering Development Status

> **Document Status:** Live Engineering Tracker  
> **Repository:** [github.com/VinitSurve/scamshield](https://github.com/VinitSurve/scamshield)  
> **Last Updated:** 2026-11-22  
> **Repository Owner & Extension Lead:** Vinit Surve (`vinit`)  
> **WhatsApp Bot Developer:** Shubham (`shubham`) & Vinit (`vinit`)

---

## 1. Executive Summary

ScamShield operates across two distinctly separated, production-grade security interfaces:

1. **Browser Extension (`extension/`):** Strictly dedicated to in-browser navigation and browsing security:
   - 32-bit k-anonymity URL reputation lookups
   - Tranco Top 100K high-trust anchor protection
   - Multi-hop redirect tracking with loop detection (>5 hops)
   - Real-time DOM zero-keystroke scanning & brand impersonation heuristics
   - Gmail spear-phishing sender spoofing guard
   - Educational interstitial navigation interception
   - Controlled Security Test Lab (`test-lab.html`)
   - Professional cybersecurity dark palette (`#080D18`, `#0D1422`, `#131D2E`, `#00B8D9` cyan accent, `#22C55E`, `#F59E0B`, `#EF4444`) with zero AI gimmick decorations.
2. **WhatsApp Bot & Threat Ingestion Pipeline (`whatsapp-bot/`):** The **PRIMARY** interface for all digital communication and screenshot scam analysis:
   - Inbound text handling: SMS text, WhatsApp forwards, copied messages, lone URLs, phone numbers, UPI identifiers, and mixed content.
   - Inbound media handling: Screenshots of fake bank KYC, OTP requests, delivery scams, electricity bills, UPI fraud, and chat conversations.
   - Dual-engine OCR pipeline: Local `Tesseract.js` OCR engine + Cloud AI Vision fallback (`qwen/qwen3.8-27b` via Groq / Gemini Vision) with strict unverified cautionary scoring for unreadable/blank images.
   - Multi-Provider AI Threat Engine: Google Gemini + Groq fast inference with multi-key pool rotation, rate-limit (HTTP 429) cooldown handling, and deterministic local heuristics fallback.
   - Safe URL Sandbox Investigator (`UrlInvestigator`): Isolated passive inspection (DNS, TLS, domain reputation, shortener unrolling) strictly protected against Server-Side Request Forgery (SSRF).
   - Conversational Session Manager (`SessionManager`): Contextual state tracking for interactive replies (`1 - Investigate link`, `2 - Explain further`, `3 - Report this scam`).
   - Standard Meta WhatsApp Cloud API webhook receiver (`POST /webhook`) + Local Demo/Simulator REST API (`POST /api/v1/bot/message`).

---

## 2. Branch & Pull Request Status Matrix

| Branch | Purpose / Scope | Target Branch | Status | Latest Commit / HEAD | PR Reference |
|---|---|---|---|---|---|
| `main` | Production & Integration Baseline | — | **Protected / Stable** | `638269b` | Baseline branch |
| `vinit-browser-extension-mvp` | Architectural Separation + Primary WhatsApp Bot + Browser Cleanups | `main` | **Active / Tested / Ready to Merge** | `HEAD` | PR #6 (Pending) |
| `vinit-add-docs` | Project Documentation & Context | `main` | **Merged into `main`** | `a4371c9` | PR #5 (Merged) |
| `vinit-scamshield-architecture` | System Architecture, Threat Model & ADRs | `main` | **Merged into `main`** | `134d965` | PR #1 / #2 (Merged) |
| `vinit-initial-setup` | Initial repository scaffolding | `main` | **Merged into `main`** | Initial | Scaffolding (Merged) |

---

## 3. Workstream Deliverables & Completion Status

### A. Browser Extension (`extension/`) — Lead: Vinit

| Module / Milestone | Priority | Status | Details |
|---|---|---|---|
| **Phase 0: Architecture & Specs** | P0 | **Completed** | Full architecture, threat modeling, ADRs, and privacy specifications in `docs/`. |
| **Phase 1: Manifest V3 Foundation** | P0 | **Completed** | Vite + React 19 + TypeScript scaffold, service worker lifecycle, minimal permissions (`storage`, `webNavigation`, `alarms`). |
| **Phase 2: URL Reputation & Privacy Engine** | P0 | **Completed** | Canonicalizer, SHA-256 hasher, 32-bit k-anonymity prefix client (`ApiClient`), L1 memory & L2 `chrome.storage.local` caching. |
| **Phase 3: Anchor & Offline Threat Protection** | P0 | **Completed** | Tranco Top 100K whitelist protection (zero false-positives for high-trust anchors) and instant offline phishing signatures. |
| **Phase 4: Navigation Interception & Interstitial** | P0 | **Completed** | `webNavigation.onBeforeNavigate` pipeline, educational warning interstitial (`interstitial.html`) with "Back to Safety" default and strict override flow. |
| **Phase 5: Redirect Protection Engine** | P1 | **Completed** | Multi-hop redirect chain tracking, loop detection (>5 hops), cross-origin bounce analysis, intermediate hop blacklisting (`RedirectTracker`). |
| **Phase 6: In-Browser Website Heuristics** | P1 | **Completed** | Content script (`content-script.ts`) DOM analysis, zero-keystroke scanning, login form detection on unrated domains, Punycode/homoglyph detection. |
| **Phase 7: Gmail Web Protection** | P2 | **Completed** | Gmail content script (`gmail.ts`) detecting display-name vs. SMTP address spoofing with injected security pills. |
| **Phase 8: Extension UI Shells** | P0 | **Completed** | Responsive Popup UI (`popup.html`), full Options/Settings page (`options.html`), threat history, telemetry toggles, and multilingual i18n support. |
| **Phase 9: Security Test Lab (Dev Mode)** | P0 (Dev) | **Completed** | Controlled testing dashboard (`test-lab.html`) with 17 synthetic/anchor/AI/path-threat test cases, real-time progress, latency tracking, and diagnostic evidence inspection. |
| **Phase 10: Architectural Cleanup** | P0 | **Completed** | Removed SMS/WhatsApp message analyzer and image screenshot scanner from browser extension popup; replaced AI sparkles/purple gradients with cybersecurity dark palette (`#080D18`, `#0D1422`, `#131D2E`, `#00B8D9`). |

### B. WhatsApp Bot & Threat Engine (`whatsapp-bot/`) — Lead: Shubham & Vinit

| Module / Milestone | Priority | Status | Details |
|---|---|---|---|
| **Phase 1: Meta Cloud API Webhook** | P0 | **Completed** | Secure `GET /webhook` verification challenge and `POST /webhook` event receiver with HMAC-SHA256 signature verification. |
| **Phase 2: SSRF Media Protection** | P0 | **Completed** | Strict media URL validation rejecting private subnets, loopback addresses (`127.0.0.1`, `10.x`, `192.168.x`, `169.254.x`), and non-Meta CDN domains. |
| **Phase 3: Tesseract OCR & AI Vision Service** | P0 | **Completed** | Inbound image analysis with `Tesseract.js` and automatic fallback to cloud AI Vision (`qwen/qwen3.8-27b`). Extracts URLs, phones, UPI IDs, brands, and urgency cues. Returns cautionary unverified score on blank/corrupted images. |
| **Phase 4: Multi-Provider AI Engine** | P0 | **Completed** | Google Gemini + Groq multi-key pool with round-robin rotation, HTTP 429 rate-limit cooldown recovery, and transparent local heuristic fallback. |
| **Phase 5: Safe URL Sandbox Investigator** | P0 | **Completed** | Isolated passive URL inspection with SSRF blocking, shortener expansion (`is.gd`, `bit.ly`), brand impersonation heuristic rules, and Tranco anchor checking. |
| **Phase 6: Conversational Session Manager** | P0 | **Completed** | In-memory session store tracking user state (`IDLE`, `AWAITING_URL_CONSENT`), previous scan context, pending target URLs, and automatic TTL expiry. |
| **Phase 7: High-Density Response Formatter** | P0 | **Completed** | Professional WhatsApp layout formatting for Threat Alerts (`CRITICAL`/`HIGH`), Caution Alerts (`SUSPICIOUS`), Clean Advisories (`SAFE`), Unverified Image alerts, URL deep scan consent prompts, and scam reporting confirmations. |
| **Phase 8: Simulator & Demo API Endpoint** | P0 | **Completed** | Dedicated `POST /api/v1/bot/message` and `POST /api/v1/bot/investigate-url` endpoints enabling instant integration testing, demonstration, and simulator interaction. |

---

## 4. WhatsApp Bot Comprehensive 20-Scenario Verification Matrix

| # | Scenario Description | Test Input Sample | Expected Verdict | Verified Result | Detection Engine |
|---|---|---|---|---|---|
| **1** | Legitimate Shipping Message | `Your order #98214 has been shipped via BlueDart...` | SAFE (Score ≤ 15%) | **PASS** | Trusted Organization Directory |
| **2** | Bank KYC Phishing Scam | `URGENT: Dear SBI Customer, bank account will be blocked...` | CRITICAL / HIGH (Score ≥ 90%) | **PASS** | Multi-Provider AI + Phishing Heuristics |
| **3** | Credential & OTP Theft Lure | `Unauthorized debit of Rs 48,500... immediately share OTP...` | CRITICAL (Score ≥ 90%) | **PASS** | Credential Theft Heuristics |
| **4** | Parcel / Courier Delivery Scam | `India Post: Your parcel cannot be delivered, pay redelivery fee...` | HIGH / CRITICAL (Score ≥ 75%) | **PASS** | Authority Impersonation + Malicious URL |
| **5** | Fraudulent UPI Collect Lure | `Rs 3,500 refund approved... approve collect request on UPI...` | HIGH (Score ≥ 80%) | **PASS** | UPI Fraud Detector |
| **6** | Lottery / Cashback Scam | `Congratulations! Won Rs 25,00,000 in KBC Jio Lucky Draw...` | HIGH / CRITICAL (Score ≥ 85%) | **PASS** | Financial Reward Lure Detector |
| **7** | Work-From-Home Job Scam | `Part-time online job: Earn Rs 3000 to 8000 daily by liking videos...` | HIGH (Score ≥ 70%) | **PASS** | Task / Advance Fee Heuristics |
| **8** | Hinglish Electricity Scam | `Aapka Bijli bill baki hai. Aaj raat connection disconnect ho jayega...` | HIGH / CRITICAL (Score ≥ 85%) | **PASS** | Utility Threat Detector |
| **9** | Hindi Banking Phishing | `प्रिय ग्राहक, आपका बैंक खाता आज ब्लॉक कर दिया जाएगा...` | HIGH / CRITICAL (Score ≥ 85%) | **PASS** | Multilingual Devanagari AI Parser |
| **10** | Screenshot Scam Analysis | Real-world ICICI fake KYC SMS screenshot (`is.gd/J9gaHq...`) | CRITICAL / HIGH (Score ≥ 90%) | **PASS** | Tesseract OCR + Vision Fallback + AI |
| **11** | Screenshot Clean Receipt | Amazon India order confirmation screenshot | SAFE (Score ≤ 20%) | **PASS** | OCR + Context Classifier |
| **12** | URL Extraction & Normalization | Mixed text containing plain, shortened, and scheme-less URLs | Extracted & Checked | **PASS** | Regex & URL Normalizer |
| **13** | Indian Mobile Phone Extraction | +91, 0-prefixed, and 10-digit Indian mobile contacts | Extracted & Tagged | **PASS** | Phone Extractor |
| **14** | UPI ID Extraction | Handles (`xxx@paytm`, `xxx@okhdfcbank`) excluding emails | Extracted & Tagged | **PASS** | UPI ID Extractor |
| **15** | Blank / Corrupted Image Handling | Tiny 1x1 blank image / blurry unreadable screenshot | CAUTION (Score: 45%, Never 0%) | **PASS** | Unverified Image Safety Guard |
| **16** | Lone URL Direct Submission | `https://sbi-kyc-verify.top` | CRITICAL / HIGH | **PASS** | URL Investigator |
| **17** | Multiple URLs Submission | Message containing multiple mirrors / phishing links | All URLs Extracted | **PASS** | Multi-URL Scanner |
| **18** | Local Heuristics Fallback | Offline evaluation when all AI providers are disabled | CRITICAL / HIGH | **PASS** | Deterministic Local Rules |
| **19** | Provider Fallback Resilience | Automatic Gemini ➔ Groq failover with telemetry | Safe / Operational | **PASS** | Multi-Key Pool Router |
| **20** | Total AI Outage Safety Net | Complete AI outage handling for electricity/KYC scams | HIGH / SCAM | **PASS** | Local Heuristic Safety Net |
| **+** | Option 1 Consent Flow | `Reply 1` ➔ Consent prompt ➔ `YES` ➔ Deep URL report | Verified | **PASS** | `SessionManager` State Machine |
| **+** | Option 2 Explain Further Flow | `Reply 2` ➔ Detailed threat breakdown + cybercrime resources | Verified | **PASS** | `ConversationFormatter` |
| **+** | Option 3 Report Scam Flow | `Reply 3` ➔ Incident logged with reference ID + 1930 portal | Verified | **PASS** | Community Reporting Pipeline |
| **+** | SSRF Defense Verification | Blocks `127.0.0.1`, `localhost`, `169.254.x`, `10.x`, `192.168.x` | Strictly Blocked | **PASS** | `UrlInvestigator.isPrivateOrReservedHost` |

---

## 5. Verification & Quality Assurance Summary

| Check | Tool / Runner | Target | Result | Details |
|---|---|---|---|---|
| **Extension Unit & Integration Tests** | Vitest v5.1.1 | `extension/tests/*.test.ts` | **97 / 97 PASS** | 15 test files passing |
| **WhatsApp Bot Tests** | Vitest v3.2.7 | `whatsapp-bot/tests/*.test.ts` | **35 / 35 PASS** | 3 test files passing (20 scenarios + SSRF + AI) |
| **Total Automated Tests** | Vitest (Dual Runner) | Entire Monorepo | **132 / 132 PASS** | **100% test pass rate across all suites** |
| **Extension TypeScript Typecheck** | `tsc --noEmit` | `extension/tsconfig.json` | **0 Errors** | Strict mode enabled |
| **WhatsApp Bot TypeScript Typecheck** | `tsc --noEmit` | `whatsapp-bot/tsconfig.json` | **0 Errors** | Clean build with zero warnings |
| **Extension Production Build** | Vite v6.4.6 + Node script | `extension/scripts/build.js` | **SUCCESS** | Bundles popup, options, interstitial, test-lab, background, content, gmail |
| **WhatsApp Bot Production Build** | `tsc` | `whatsapp-bot/` ➔ `dist/` | **SUCCESS** | Standalone Node.js service ready on port 3001 |
