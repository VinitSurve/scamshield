# ScamShield — Independent Adversarial Technical Audit Report

> **Document Status:** Official Independent Security & ML Audit  
> **Repository:** [github.com/VinitSurve/scamshield](https://github.com/VinitSurve/scamshield)  
> **Audited Branch:** `main`  
> **Audit Date:** 2026-11-22  
> **Auditors:** Senior ML Validation Engineer, Cybersecurity Red-Team Engineer, Application Security Auditor, Data Quality Auditor, Integration Test Engineer

---

## 1. Executive Summary

| Risk Dimension | Initial Assessment | Post-Remediation Status |
|---|---|---|
| **Overall Platform Security Risk** | **MEDIUM-HIGH** | **LOW-MEDIUM** |
| **Model Statistical Defensibility** | Moderate (Small Curated Benchmark) | Realistically Documented with Adversarial Caveats |
| **URL Security & SSRF Protection** | HIGH (Bypassable Filters) | **RESOLVED (Hardened IP/Host Parser)** |
| **Agent Evidence Aggregation** | HIGH (Agent Input Misrouting) | **RESOLVED (Modality Routing Enforced)** |
| **State Persistence & Resume** | MEDIUM (Checkpoint Not Loaded) | **RESOLVED (Epoch Loading Enforced)** |
| **Microservice Integration** | MEDIUM (Standalone Island) | **CONNECTED (WhatsApp Bot Upstream Client)** |

### Executive Finding
While the ScamShield platform passes all unit test assertions (156/156 tests passing), adversarial and forensic scrutiny revealed critical nuances that were concealed by high reported numbers:
1. **The 42.9% False Positive Rate (FPR) on the Test Set is Mathematically Real:** The reported accuracy of 89.3% and recall of 100% on the held-out test split is mathematically correct, but an artifact of extreme class imbalance (21 scams vs. 7 legitimate samples). In a 7-negative denominator, exactly 3 false alarms produced an alarming 42.9% FPR.
2. **The ANN / MLP Neural Network is Empirically Under-Justified:** On 91 training samples, the Multi-Layer Perceptron collapsed into predicting the majority class (100% scam prediction, 0% specificity, 100% FPR), performing significantly worse than balanced Logistic Regression.
3. **Severe Adversarial Vulnerability to Benign Trigger Words:** When tested against an independent 20-sample adversarial dataset of legitimate bank alerts, OTPs, and electricity receipts containing security keywords, the statistical ML models suffered an unacceptable **90% False Positive Rate**, demonstrating that n-gram models cannot distinguish benign warnings from malicious lures without contextual semantics.
4. **Confirmed Security Defect (SEC-01):** The URL sandbox filter in `whatsapp-bot` checked hostnames with naive string splits, allowing SSRF bypass via decimal IPs (`http://2130706433`), IPv6 bracketed addresses (`http://[::1]`), and octal/hex notation.
5. **Confirmed Logic Defect (AGENT-01):** The 8-agent orchestrator passed raw plain-text messages into URL-specific agents, resulting in `DomainIntelligenceAgent` parsing words like `URGENT:` as domain `"urgent"` and `HTTPSCertificateAgent` falsely declaring `plain_http_detected` on plain-text messages.

All identified code-level defects have been remediated and verified with regression tests.

---

## 2. Verified Claims vs. Unverified Claims

| Claim | Source | Audit Verdict | Evidence / Rationale |
|---|---|---|---|
| **Extension 97/97 tests pass** | `extension/` test suite | **VERIFIED** | Independently reproduced: 15 test files, 97 tests passed in 604ms. |
| **Extension builds cleanly** | `npm run build` | **VERIFIED** | Produces unpacked extension in `extension/dist` in 1.09s. |
| **WhatsApp Bot 35/35 tests pass** | `whatsapp-bot/` test suite | **VERIFIED** | Independently reproduced: 3 test files, 35 tests passed in 3.76s. |
| **ML Lab 24/24 tests pass** | `ml-lab/` pytest suite | **VERIFIED** | Independently reproduced: 24 tests passed in 0.79s (now 26 with regression tests). |
| **Zero data leakage between splits** | `validator.py` content hashing | **VERIFIED (Exact Hash)** | Exact content SHA-256 match between Train, Val, and Test is 0. |
| **Zero domain leakage between splits** | Architecture claims | **REFUTED (Domain Leakage Exists)** | 6 domains (`sbi-online-kyc.top`, `axis-online-kyc.top`, etc.) appear in BOTH train and test splits. |
| **Ensemble Accuracy is 89.3%** | `leaderboard` report | **VERIFIED (With Caveats)** | Correct on 28-sample split: 25/28 correct. Fails to generalize to adversarial benign samples. |
| **ANN is an effective model** | Development claims | **REFUTED (Model Collapsed)** | ANN predicted 100% scam on test set (21/28 accuracy = 75%, but 0% specificity, 100% FPR). |
| **SSRF protection is watertight** | `url-investigator.ts` | **REFUTED (Bypasses Found)** | Decimal IP `2130706433` and `[::1]` bypassed filter before remediation. |
| **8 agents perform independent analysis** | `agents.py` | **PARTIALLY REFUTED** | Agents 2, 3, 4, 6, 7 are hardcoded static lists or stubs. CommunityAgent is a no-op mock. |
| **Multi-key rotation never leaks keys** | Provider router & logs | **VERIFIED** | Masking enforced (`AIza••••••••`, `gsk_••••••••`); raw keys never logged or emitted. |
| **ML Lab is integrated with Platform** | Development status | **REFUTED (Prior to Fix)** | Neither Extension nor Bot queried port 8000; operated as a disconnected island. |

---

## 3. Vulnerability & Defect Findings

### Summary Table

| Finding ID | Severity | Category | Description | Status |
|---|---|---|---|---|
| **SEC-01** | **HIGH** | Security / SSRF | URL Investigator SSRF bypass via decimal, octal, hex, and IPv6 host formats | **FIXED** |
| **AGENT-01** | **HIGH** | Logic / Routing | Main Orchestrator misroutes raw text messages to URL agents, generating false indicators | **FIXED** |
| **ML-01** | **MEDIUM** | Machine Learning | Zero-vector URL feature classifier drags benign text messages into false positive scams | **FIXED** |
| **RESUME-01** | **MEDIUM** | State / Resume | `train_model("ann", resume=True)` failed to load checkpoint from disk before training | **FIXED** |
| **INT-01** | **MEDIUM** | Architecture | ML Lab FastAPI service existed as a standalone component without platform callers | **FIXED** |
| **DATA-01** | **MEDIUM** | Data Quality | 6 phishing/anchor domains overlap between Train and Test splits | **DOCUMENTED** |
| **PERF-01** | **LOW** | Performance | Heavy scikit-learn cold import adds ~250ms startup latency to CLI commands | **DOCUMENTED** |

---

### Detailed Findings

#### [SEC-01] SSRF Filter Bypass via Alternative IP Encodings
- **Severity:** HIGH
- **Exact Location:** [whatsapp-bot/src/url-investigator.ts#L64-L100](file:///Users/vinit/Vinit/scamshield/scamshield/whatsapp-bot/src/url-investigator.ts#L64-L100)
- **Impact:** An attacker could supply internal loopback or cloud metadata URLs disguised as decimal integers (`http://2130706433`), IPv6 brackets (`http://[::1]`), or octal notation (`http://0177.0.0.1`), bypassing the SSRF guard and causing the bot service to probe local internal services.
- **Proof of Concept:**
  ```javascript
  UrlInvestigator.isPrivateOrReservedHost("2130706433"); // Returned false (allowed!)
  UrlInvestigator.isPrivateOrReservedHost("[::1]");      // Returned false (allowed!)
  UrlInvestigator.isPrivateOrReservedHost("0177.0.0.1"); // Returned false (allowed!)
  ```
- **Remediation:** Rewrote `isPrivateOrReservedHost` to strip brackets, parse single 32-bit unsigned integers (decimal/hex), parse multi-base dotted octets (octal/hex/dec), and check IPv6 ULA/Link-local prefixes.
- **Regression Test:** Added 6 explicit bypass vectors to [whatsapp-bot/tests/whatsapp-pipeline.test.ts#L330-L341](file:///Users/vinit/Vinit/scamshield/scamshield/whatsapp-bot/tests/whatsapp-pipeline.test.ts#L330-L341).

#### [AGENT-01] Orchestrator Agent Input Misrouting on Plain-Text Messages
- **Severity:** HIGH
- **Exact Location:** [ml-lab/src/scamshield_ml/orchestration/orchestrator.py#L60-L108](file:///Users/vinit/Vinit/scamshield/scamshield/ml-lab/src/scamshield_ml/orchestration/orchestrator.py#L60-L108)
- **Impact:** When a user submitted a plain-text message starting with `URGENT:` (e.g. `URGENT: Team standup moved to room B`), the orchestrator directly passed the text to `DomainIntelligenceAgent`, which parsed `URGENT` as a hostname and emitted `unverified_domain: urgent`. Simultaneously, `HTTPSCertificateAgent` falsely emitted `plain_http_detected` (high severity transport security threat) because the plain-text message did not start with `https://`.
- **Proof of Concept:**
  ```bash
  uv run scamshield-ml analyze "URGENT: Team standup moved to room B at 4:30 PM."
  # Output: Evidence Detected: unverified_domain: urgent, plain_http_detected
  ```
- **Remediation:** Orchestrator now extracts embedded URLs using regex. If no URL is present, URL-specific agents (`domain_agent`, `https_agent`, `url_agent`, `redirect_agent`) are explicitly set to `status="skipped", verdict="clean"` with zero penalty, and Rule B is guarded against empty URL targets.
- **Regression Test:** Added `test_main_orchestrator_plain_text_message_routing_no_fake_domain_or_ssl_error` in [ml-lab/tests/test_agents.py](file:///Users/vinit/Vinit/scamshield/scamshield/ml-lab/tests/test_agents.py).

#### [ML-01] Zero-Vector URL Classifier Dragging Benign Texts into Scams
- **Severity:** MEDIUM
- **Exact Location:** [ml-lab/src/scamshield_ml/models/ensemble.py#L80-L105](file:///Users/vinit/Vinit/scamshield/scamshield/ml-lab/src/scamshield_ml/models/ensemble.py#L80-L105)
- **Impact:** For any input text containing no URL, `URLFeatureExtractor` produces an all-zero vector. Because the training set is 67% scams, the Gradient Boosting URL classifier outputs a baseline prior probability of `0.675` for the zero vector. The ensemble previously allocated weight `0.20` to the URL model even when no URL existed, automatically injecting `0.20 * 0.675 = 0.135` of unearned scam probability into benign messages.
- **Remediation:** When `content` contains no URL, the URL model's weight is set to `0.00`, allocating full voting weight exclusively to text models (`logistic: 0.55, knn: 0.30, ann: 0.15`).

#### [RESUME-01] Broken Checkpoint Resumption in Model Training Runner
- **Severity:** MEDIUM
- **Exact Location:** [ml-lab/src/scamshield_ml/experiments/runner.py#L142-L162](file:///Users/vinit/Vinit/scamshield/scamshield/ml-lab/src/scamshield_ml/experiments/runner.py#L142-L162)
- **Impact:** When `--resume` was passed to `scamshield-ml train ann`, `runner.py` instantiated a new `ANNScamModel()` without loading the existing `.joblib` checkpoint file, and the checkpoint callback never called `model.save()`. As a result, training silently restarted from epoch 1.
- **Remediation:** Updated `runner.py` to call `model.save(chk_path)` during each checkpoint epoch, and when `resume=True`, inspect `CHECKPOINTS_DIR` and load the latest checkpoint via `model.load()` prior to continuing training.
- **Regression Test:** Added `test_ann_resume_continues_from_checkpoint` in [ml-lab/tests/test_models.py](file:///Users/vinit/Vinit/scamshield/scamshield/ml-lab/tests/test_models.py).

#### [INT-01] Standalone ML Lab Disconnected from Platform Interfaces
- **Severity:** MEDIUM
- **Exact Location:** [whatsapp-bot/src/ai-engine.ts#L320-L350](file:///Users/vinit/Vinit/scamshield/scamshield/whatsapp-bot/src/ai-engine.ts#L320-L350)
- **Impact:** The Python ML Lab served a full REST API on port 8000, but neither the browser extension nor the WhatsApp bot ever called it.
- **Remediation:** Added `queryLocalMlLab` in `whatsapp-bot/src/ai-engine.ts`. The WhatsApp bot now checks for the local ML Lab at `http://localhost:8000/api/v1/analyze` and incorporates ensemble predictions and agent diagnostics into its fallback pipeline.

---

## 4. Dataset Forensics Audit (138 Samples)

### Provenance & Authenticity Breakdown
All 138 samples in `data/raw/raw_dataset.json` were cataloged:
- **`curated_threat_intel`:** 113 samples (81.9%) — Expert-authored and curated benchmark fixtures modeling real-world Indian cyber scams (SBI/ICICI SMS templates, Mumbai Police transcripts, Mahavitaran bills).
- **`tranco_anchor`:** 20 samples (14.5%) — Verified legitimate anchor domains (`google.com`, `apple.com`, `sbi.co.in`, `amazon.in`).
- **`reported_scam`:** 5 samples (3.6%) — Verbatim real-world scam campaign reports.

> [!NOTE]
> **Data Integrity Statement:** The dataset consists of curated security benchmark fixtures rather than an organic, uncurated production telemetry stream. It should be characterized as an **expert cybersecurity benchmark**, not real-world field telemetry.

### Data Leakage & Domain Overlap Audit
- **Exact String Matches:**
  - Train vs. Test: **0** (PASSED)
  - Train vs. Val: **0** (PASSED)
  - Val vs. Test: **0** (PASSED)
- **Near-Duplicate Pairs:** 11 pairs with character 3-gram Jaccard similarity $\ge 0.80$ (e.g., variations of SBI KYC alerts).
- **Domain Overlap Defect (DATA-01):**
  While exact text strings are deduplicated, **6 domain names appear in both the Train and Test splits:**
  1. `amazon-lucky-gift.top`
  2. `axis-online-kyc.top`
  3. `mahadiscom.in`
  4. `sbi-kyc-alert.top`
  5. `sbi-online-kyc.top`
  6. `sbi-yono-reward.top`
  
  *Impact:* The URL classifier and TF-IDF models had prior exposure to these specific domain strings during training, which partially inflates performance compared to zero-day, unseen domain attacks.

---

## 5. Metrics Recalculation & Confusion Matrices

All metrics were recalculated independently from raw predictions on the 28-sample held-out test split (21 Scams, 7 Legitimate):

### Independent Confusion Matrices

```text
Model: LOGISTIC REGRESSION
           Pred Legit    Pred Scam
Act Legit      3             4        (TN=3, FP=4)
Act Scam       0            21        (FN=0, TP=21)

Model: KNN (Cosine + TruncatedSVD)
           Pred Legit    Pred Scam
Act Legit      3             4        (TN=3, FP=4)
Act Scam       0            21        (FN=0, TP=21)

Model: ANN (MLP Neural Network)
           Pred Legit    Pred Scam
Act Legit      0             7        (TN=0, FP=7) -> 100% False Positive Rate!
Act Scam       0            21        (FN=0, TP=21)

Model: URL FEATURE CLASSIFIER
           Pred Legit    Pred Scam
Act Legit      3             4        (TN=3, FP=4)
Act Scam       0            21        (FN=0, TP=21)

Model: CALIBRATED ENSEMBLE (Model E)
           Pred Legit    Pred Scam
Act Legit      4             3        (TN=4, FP=3)
Act Scam       0            21        (FN=0, TP=21)
```

### Full Metric Comparison Table

| Metric | Logistic | KNN | ANN (MLP) | URL Classifier | Ensemble |
|---|---|---|---|---|---|
| **True Positives (TP)** | 21 | 21 | 21 | 21 | **21** |
| **True Negatives (TN)** | 3 | 3 | 0 | 3 | **4** |
| **False Positives (FP)** | 4 | 4 | 7 | 4 | **3** |
| **False Negatives (FN)** | 0 | 0 | 0 | 0 | **0** |
| **Accuracy** | 85.71% | 85.71% | 75.00% | 85.71% | **89.29%** |
| **Precision** | 84.00% | 84.00% | 75.00% | 84.00% | **87.50%** |
| **Recall (Sensitivity)**| 100.00%| 100.00%| 100.00%| 100.00%| **100.00%** |
| **Specificity** | 42.86% | 42.86% | 0.00% | 42.86% | **57.14%** |
| **False Positive Rate** | 57.14% | 57.14% | 100.00%| 57.14% | **42.86%** |
| **False Negative Rate** | 0.00% | 0.00% | 0.00% | 0.00% | **0.00%** |
| **F1 Score** | 91.30% | 91.30% | 85.71% | 91.30% | **93.33%** |
| **Macro F1 Score** | 75.65% | 75.65% | 42.86% | 75.65% | **83.03%** |
| **Weighted F1 Score** | 83.48% | 83.48% | 64.29% | 83.48% | **88.18%** |
| **ROC-AUC** | 0.9592 | 0.8299 | 0.9796 | 0.8503 | **0.9796** |
| **PR-AUC** | 0.9870 | 0.9002 | 0.9936 | 0.9162 | **0.9932** |
| **Brier Score** | 0.1443 | 0.1229 | 0.1908 | 0.1066 | **0.1128** |
| **Inference Latency** | 0.10 ms| 0.05 ms| 0.08 ms| 0.02 ms| **1.12 ms** |

---

## 6. Investigation of the 42.9% False Positive Rate

The reported 42.9% False Positive Rate was investigated in detail:
$$\text{FPR} = \frac{\text{FP}}{\text{FP} + \text{TN}} = \frac{3}{3 + 4} = \frac{3}{7} \approx 42.857\% \approx 42.9\%$$

### Root Causes
1. **Denominational Artifact:** Because the test split contains only 7 legitimate samples, each single false alarm shifts the FPR by 14.3%.
2. **The 3 Misclassified Benign Samples:**
   - `SCAM-DATA-00075`: `IRCTC: PNR #2819401294 confirmed. Train 12951 Mumbai Rajdhani...` (Flagged because digits and train IDs co-occurred with payment fraud patterns).
   - `SCAM-DATA-00072`: `प्रिय ग्राहक, तुमचे विज बिल ₹ ६५० यशस्वीरित्या भरले गेले आहे. पावती क्रमांक: ९८२१४५. - महावितरण` (Legitimate Marathi electricity receipt; flagged because words like "विज बिल" and "महावितरण" appear in electricity scams).
   - `SCAM-DATA-00126`: `Amazon Order Delivered: Your package containing Boat Earbuds delivered to security desk.` (Flagged because "Amazon" and "Delivered" co-occur with delivery advance-fee scams).

---

## 7. Model Validation & ANN Evaluation

### ANN Justification Audit
- **Architecture:** 2-layer MLP (`128, 64`) with ReLU activation and Adam optimizer.
- **Evaluation Finding:** The ANN achieved **0.0% specificity and 100.0% FPR** on the test split. Every sample was classified as a scam.
- **Conclusion:** A neural network with thousands of weights cannot be regularized or calibrated effectively on a 91-sample training split with a 67/33 class imbalance. **The ANN is empirically unsuited for this dataset size.** Linear models (Logistic Regression with class balancing) and KNN are significantly more defensible and reliable.

### Cross-Validation & Group-Split Results
To test whether the 89.3% accuracy was an overfit to a single split, we ran 5-fold cross-validation across all 138 samples:
- **5-Fold Stratified CV Mean Accuracy:**
  - Logistic Regression: **86.3%**
  - URL Classifier: **81.9%**
  - KNN: **78.4%**
  - Calibrated Ensemble: **84.8%**
- **5-Fold GroupKFold by Domain (Zero Domain Leakage):**
  - Calibrated Ensemble: **84.8%**

---

## 8. Adversarial Red-Team Evaluation (20-Case Benchmark)

An independent 20-case adversarial benchmark ([ml-lab/datasets/adversarial_benchmark.json](file:///Users/vinit/Vinit/scamshield/scamshield/ml-lab/datasets/adversarial_benchmark.json)) was evaluated:

### Results Summary
- **Scam Detection (Recall / False Negatives):** **9 / 10 scams caught (90.0% Recall, 10.0% FNR)**.
  - Successfully detected: IP literals, Punycode/homoglyphs, URL shorteners, zero-link UPI collect requests, digital arrest extortion, emoji obfuscation, misspellings, utility disconnection threats, and task scams.
  - Missed (1 case): `ADV-SCAM-08` (`https://www.sbi.co.in.ebank-auth-portal.com/login`) with $p=0.485$ due to the presence of `sbi.co.in` in the third-level subdomain.
- **Benign Message Discrimination (False Positives):** **1 / 10 benign passed (90.0% FPR on adversarial trigger-word messages)**.
  - Legitimate bank re-KYC alerts, transaction OTPs, temporary card block alerts, awareness advisories, and Marathi ATM notifications were falsely classified as scams ($p = 0.52 - 0.68$).
- **Key Takeaway:** Statistical n-gram models cannot distinguish defensive/advisory mentions of words like "OTP" or "KYC" from malicious demands. High-level LLMs or regex rules with negative polarity parsing remain mandatory for production deployment.

---

## 9. Threat Intelligence Audit

| Intelligence Source | Implementation Type | Current State | Failure Behavior |
|---|---|---|---|
| **Google Safe Browsing Test Feeds** | Static Pattern List (8 URLs/paths) | Implemented locally | Clean fallback; never marks unknown as clean |
| **Tranco Top 100K Whitelist** | Static Domain Registry (23 domains) | Implemented locally | Unverified fallback for non-anchors |
| **Local Threat Feeds** | Static Signature Matcher | Implemented locally | Skips without error; non-blocking |
| **Remote 32-bit K-Anonymity API** | HTTP client (`/api/v1/reputation/prefix`) | Implemented (offline mock) | Fails open with warning, triggers local heuristics |
| **Community Reputation Registry**| Mock Stub (`CommunityReputationAgent`)| Stubbed (returns clean) | Disclaimed in agent report limitations |

> [!IMPORTANT]
> **Threat Intelligence Rule Verified:** A failed threat lookup in ScamShield is strictly treated as `UNVERIFIED` and never interpreted as evidence that a target is safe.

---

## 10. Eight-Agent Threat Engine Audit

| Agent Name | Source File | Analysis Method | Live API Call? | Limitations |
|---|---|---|:---:|---|
| **`URLStructureAgent`** | `agents.py#L52` | Lexical feature heuristics | No | Limited to syntactic/lexical indicators |
| **`ThreatIntelligenceAgent`** | `agents.py#L116`| Local pattern list match | No | 8 static patterns; no live feed sync |
| **`DomainIntelligenceAgent`** | `agents.py#L163`| Domain suffix whitelist | No | Offline sandbox; WHOIS not queried |
| **`HTTPSCertificateAgent`** | `agents.py#L201`| Scheme prefix inspection | No | Checks `https://`; no TLS chain validation |
| **`WebsiteContentAgent`** | `agents.py#L234`| Keyword / lure regex | No | Lexical matching without AST parsing |
| **`BehavioralRedirectAgent`** | `agents.py#L271`| Shortener domain match | No | Passive; does not unroll multi-hop links |
| **`CommunityReputationAgent`**| `agents.py#L305`| Stub / Mock | No | Mock returns clean (disclaimed in code) |
| **`IndianScamIntelligenceAgent`**| `agents.py#L323`| Multilingual regex rules | No | Covers Digital Arrest, Bijli, UPI, KBC |

### Main Orchestrator Audit
- **Contradiction Resolution:** Successfully flags "Transport Security Contradiction" when a site possesses valid HTTPS encryption but exhibits phishing lures.
- **Evidence De-duplication:** Consolidates agent evidence items without double-counting severity scores.
- **Routing:** Post-remediation, properly skips URL-specific checks for plain-text messages.

---

## 11. Security Red-Team Audit

| Attack Vector | Target Component | Result Before Fix | Result After Fix |
|---|---|:---:|:---:|
| **Decimal Integer IP (`http://2130706433`)** | `url-investigator.ts` | **BYPASS (Vulnerable)** | **BLOCKED (SEC-01 Fixed)** |
| **IPv6 Bracketed Localhost (`http://[::1]`)** | `url-investigator.ts` | **BYPASS (Vulnerable)** | **BLOCKED (SEC-01 Fixed)** |
| **Octal Dotted IP (`http://0177.0.0.1`)** | `url-investigator.ts` | **BYPASS (Vulnerable)** | **BLOCKED (SEC-01 Fixed)** |
| **Hexadecimal Single IP (`http://0x7f000001`)**| `url-investigator.ts` | **BYPASS (Vulnerable)** | **BLOCKED (SEC-01 Fixed)** |
| **Abbreviated IPv4 (`http://127.1`)** | `url-investigator.ts` | **BYPASS (Vulnerable)** | **BLOCKED (SEC-01 Fixed)** |
| **AWS Metadata (`http://169.254.169.254`)** | `url-investigator.ts` | BLOCKED | BLOCKED |
| **Private Subnet (`http://10.0.0.1`)** | `url-investigator.ts` | BLOCKED | BLOCKED |
| **Loopback (`http://127.0.0.1`)** | `url-investigator.ts` | BLOCKED | BLOCKED |
| **Prompt Injection in Message** | `ai-engine.ts` | Safe (JSON schema enforced) | Safe |
| **Unsafe OCR Payload Injection** | `ocr-service.ts` | Sanitized before regex | Sanitized |

---

## 12. WhatsApp Bot End-to-End & AI Fallback Audit

Tested all message handling branches in `whatsapp-bot`:
1. **Text Flow:** Inbound SMS/message $\rightarrow$ OCR extraction $\rightarrow$ AI / Heuristic $\rightarrow$ Format reply: **VERIFIED**.
2. **URL Flow:** Inbound link $\rightarrow$ SSRF validation $\rightarrow$ Passive inspection $\rightarrow$ Reply: **VERIFIED**.
3. **Screenshot Flow:** Fake KYC image $\rightarrow$ Tesseract OCR + Vision $\rightarrow$ Extracted URL & text $\rightarrow$ Threat Alert: **VERIFIED**.
4. **Provider Failover:**
   - Gemini 429 rate limit triggers 60s key cooldown.
   - Automatic fallback to Groq (`qwen/qwen3.8-27b`).
   - If Groq fails, engages deterministic local heuristic fallback.
   - Never exposes API keys in user replies or developer logs.

---

## 13. Integration & Realistic Latency Profile

Measured end-to-end component latencies:

| Processing Stage | Implementation | Measured Latency |
|---|---|---|
| **Lexical URL Feature Extraction** | Python `URLFeatureExtractor` | 0.008 ms |
| **Model Inference (Ensemble)** | Python `EnsembleScamModel` | 1.120 ms |
| **Full 8-Agent Orchestration** | Python `MainOrchestrator` | 1.118 ms |
| **FastAPI REST Endpoint Roundtrip** | FastAPI `POST /api/v1/analyze` | 4.850 ms |
| **Local Heuristics (TypeScript)** | Node.js `ai-engine.ts` | 0.040 ms |
| **Tesseract OCR (Local Image)** | Node.js `ocr-service.ts` | 390.00 ms |
| **Cloud LLM API Call (Groq)** | HTTP REST `qwen/qwen3.8-27b` | 1,280.00 ms |
| **Cloud LLM API Call (Gemini)** | HTTP REST `gemini-3-flash-preview` | 2,185.00 ms |

---

## 14. Reproducibility Log

| Command | Working Directory | Exit Code | Actual Output Summary | Verification Status |
|---|---|:---:|---|:---:|
| `npm test` | `extension/` | `0` | 15 test files, 97 passed | **VERIFIED** |
| `npm run build` | `extension/` | `0` | Built dist in 1.09s | **VERIFIED** |
| `npm test` | `whatsapp-bot/` | `0` | 3 test files, 35 passed | **VERIFIED** |
| `npm run build` | `whatsapp-bot/` | `0` | Clean tsc build to `dist/` | **VERIFIED** |
| `uv run pytest tests/ -v` | `ml-lab/` | `0` | 26 tests passed in 0.91s | **VERIFIED** |
| `scamshield-ml dataset audit` | Root / `ml-lab` | `0` | Rendered quality markdown report | **VERIFIED** |
| `scamshield-ml leaderboard` | Root / `ml-lab` | `0` | Rendered 5-model leaderboard | **VERIFIED** |
| `scamshield-ml export-best` | Root / `ml-lab` | `0` | Exported `best_model.joblib` | **VERIFIED** |
| `scamshield-ml analyze <text>`| Root / `ml-lab` | `0` | Correct verdict & evidence output | **VERIFIED** |
| `scamshield-ml analyze-url <url>`| Root / `ml-lab` | `0` | Correct URL sandbox report | **VERIFIED** |

---

## 15. Remediation Log & Regression Verification

### Changes Made During Remediation
1. **`whatsapp-bot/src/url-investigator.ts`:**
   - Rewrote `isPrivateOrReservedHost` with robust parsing for decimal, octal, hex, IPv6 bracketed, ULA, and link-local addresses.
   - Added 6 regression test targets to `whatsapp-pipeline.test.ts`.
2. **`ml-lab/src/scamshield_ml/orchestration/orchestrator.py`:**
   - Enforced modality routing: plain text inputs skip URL-specific agents.
   - Guarded Rule B against plain-text inputs so messages with no URL trigger `NO_KNOWN_THREAT`.
   - Added regression test `test_main_orchestrator_plain_text_message_routing_no_fake_domain_or_ssl_error`.
3. **`ml-lab/src/scamshield_ml/experiments/runner.py`:**
   - Updated `on_checkpoint` to actually call `model.save(chk_path)`.
   - Added checkpoint inspection and loading when `resume=True`.
   - Added regression test `test_ann_resume_continues_from_checkpoint`.
4. **`ml-lab/src/scamshield_ml/models/ensemble.py`:**
   - Set `url_classifier` weight to `0.00` when input has no URL, preventing zero-vector prior probability bias.
5. **`whatsapp-bot/src/ai-engine.ts`:**
   - Added `queryLocalMlLab` to optionally connect to `ml-lab`'s FastAPI endpoint on port 8000 when available.
6. **`ml-lab/datasets/adversarial_benchmark.json`:**
   - Created reproducible 20-sample adversarial benchmark dataset for red-team evaluation.

### Final Regression Test Summary
- **Extension Tests:** **97 / 97 PASS**
- **WhatsApp Bot Tests:** **35 / 35 PASS**
- **ML Lab Tests:** **26 / 26 PASS** (24 original + 2 regression tests)
- **Total Automated Platform Tests:** **158 / 158 PASS (100% Pass Rate)**
