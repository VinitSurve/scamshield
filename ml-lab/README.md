# ScamShield Intelligence Lab (`ml-lab/`)

> **Autonomous Machine Learning Pipeline, Multi-Agent Threat Analysis Engine, and Platform Integration for ScamShield Cybersecurity**

---

## 1. Executive Summary

ScamShield Intelligence Lab (`ml-lab/`) is an end-to-end, production-grade machine learning and multi-agent threat intelligence sub-system developed specifically to detect and analyze digital cyber frauds, phishing campaigns, social engineering schemes, and multimodal scam messages targeting Indian internet and banking users.

Unlike generic spam filters, ScamShield Intelligence Lab addresses the unique characteristics of Indian digital fraud:
- **Multilingual & Code-Mixed Text:** Deep support for Indian English, Devanagari Hindi, Marathi, and Romanized Hinglish/Marathi.
- **High-Velocity Indian Fraud Vectors:** Dedicated pattern recognition for Digital Arrest impersonation (Mumbai Police / CBI), Electricity disconnection threats (Mahavitaran / Bijli bills), Fake Banking KYC account suspension lures (SBI, HDFC, ICICI, Axis), UPI collect request fraud, and India Post parcel re-delivery lures.
- **Explainable Multi-Agent Intelligence:** 8 specialized security agents coordinated by an evidence-aware orchestrator with automated contradiction resolution (e.g. flagging TLS/HTTPS certificates on malicious phishing kits).
- **Resilient Multi-Key Cloud Fallback:** Round-robin key rotation across Google Gemini and Groq API keys with automated rate-limit cooldown (HTTP 429) and deterministic local heuristics.

---

## 2. System Architecture

```text
                                  ┌───────────────────────────────┐
                                  │      ScamShield Platform      │
                                  │  (Browser Extension & Bot)    │
                                  └───────────────┬───────────────┘
                                                  │
                                                  ▼ REST (FastAPI)
┌─────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                   ScamShield ML Lab (`serve`)                                   │
│                                                                                                 │
│   ┌────────────────────────────────────────┐       ┌────────────────────────────────────────┐   │
│   │        Trained Ensemble Model          │       │    8-Agent Threat Analysis Engine      │   │
│   │                                        │       │                                        │   │
│   │  • Model A: TF-IDF + Logistic Reg      │       │  1. URLStructureAgent                  │   │
│   │  • Model B: TruncatedSVD + KNN         │  ◄──► │  2. ThreatIntelligenceAgent            │   │
│   │  • Model C: MLP Neural Network (ANN)   │       │  3. DomainIntelligenceAgent            │   │
│   │  • Model D: URL Structural Classifier  │       │  4. HTTPSCertificateAgent              │   │
│   │  • Model E: Soft-Voting Ensemble       │       │  5. WebsiteContentAgent                │   │
│   │                                        │       │  6. BehavioralRedirectAgent            │   │
│   └────────────────────────────────────────┘       │  7. CommunityReputationAgent           │   │
│                                                    │  8. IndianScamIntelligenceAgent        │   │
│                                                    └───────────────────┬────────────────────┘   │
│                                                                        │                        │
│                                                    ┌───────────────────▼────────────────────┐   │
│                                                    │       Multi-Key Cloud AI Fallback      │   │
│                                                    │  • Google Gemini Pool (Key Rotation)   │   │
│                                                    │  • Groq Pool (qwen/qwen3.8-27b)        │   │
│                                                    │  • 429 Auto-Cooldown & Recovery        │   │
│                                                    └────────────────────────────────────────┘   │
└────────────────────────────────────────────────┬────────────────────────────────────────────────┘
                                                 │
                                                 ▼
┌─────────────────────────────────────────────────────────────────────────────────────────────────┐
│                      SQLite-Backed Persistent State Store (`state/scamshield_ml.db`)             │
│   • 12 Pipeline Phases Tracking • Active Job Leases • Experiment Leaderboard • Structured Logs  │
└─────────────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Dataset Engineering & Zero-Leakage Quality Control

The ML pipeline operates on the curated **ScamShield-IndiaFirst-Cybersecurity-Benchmark**:
- **Total Unique Samples:** 138 high-signal security samples
- **Splits:**
  - **Train Split (70%):** 91 samples
  - **Validation Split (15%):** 19 samples
  - **Held-Out Test Split (15%):** 28 samples
- **Languages Covered:** English (`en`), Hinglish (`hinglish`), Devanagari Hindi (`hi`), Marathi (`mr`), Romanized Marathi (`romanized_mr`).
- **Fraud Categories:** Banking KYC Phishing, UPI Collect Fraud, Electricity Disconnection, Delivery Redelivery Fee, Lottery / KBC Advance Fee, Digital Arrest, Part-Time Job Scam, OTP/Credential Theft, and Legitimate Transactions/Shipping.
- **Leakage Prevention:**
  - SHA-256 exact deduplication
  - Character 3-gram Jaccard near-duplicate clustering
  - Verified **ZERO OVERLAP** between Train, Validation, and Test splits (`leakage = 0`).

---

## 4. Model Architectures & Benchmark Leaderboard

All models are trained, tuned, and evaluated on the strictly held-out 28-sample test split.

### Model Leaderboard (Held-Out Test Split)

| Rank | Model Name | Accuracy | Precision | Recall | Macro F1 | F1 Score | FPR | ROC-AUC | Latency |
|---|---|---|---|---|---|---|---|---|---|
| **#1** | **`ensemble`** | **89.3%** | **87.5%** | **100.0%** | **83.0%** | **93.3%** | **42.9%** | **0.980** | **1.1ms** |
| **#2** | **`url`** | 85.7% | 84.0% | 100.0% | 75.6% | 91.3% | 57.1% | 0.850 | 0.0ms |
| **#3** | **`knn`** | 85.7% | 84.0% | 100.0% | 75.6% | 91.3% | 57.1% | 0.830 | 0.0ms |
| **#4** | **`logistic`** | 85.7% | 84.0% | 100.0% | 75.6% | 91.3% | 57.1% | 0.959 | 0.1ms |
| **#5** | **`ann`** | 75.0% | 75.0% | 100.0% | 42.9% | 85.7% | 100.0% | 0.980 | 0.0ms |

### Model Details
1. **Model A (`logistic_regression`):**
   - Word (1-2 gram) + Character (3-5 gram) sublinear TF-IDF representation.
   - Class-balanced L2-regularized Logistic Regression.
2. **Model B (`knn`):**
   - TF-IDF + TruncatedSVD (LSA dimensionality reduction) with Cosine K-Nearest Neighbors.
3. **Model C (`ann`):**
   - Multilayer Perceptron (MLP) Neural Network with warm-start checkpointing, epoch-by-epoch training logs, and `--resume` support. Checkpoints stored in `state/checkpoints/`.
4. **Model D (`url_classifier`):**
   - Gradient Boosting Classifier trained on 20 lexical & structural URL features (Shannon host entropy, suspicious TLDs, punycode, brand mismatch, subdomains, port anomalies).
5. **Model E (`ensemble`):**
   - Dynamic soft-voting ensemble combining Models A, B, C, and D with adaptive weights depending on input modality.

---

## 5. Multi-Agent Threat Intelligence Engine

The orchestration layer contains 8 typed, specialized security agents:

1. **`URLStructureAgent`:** Analyzes URL syntax, Punycode homoglyphs, suspicious disposable TLDs (`.top`, `.xyz`), shortener obfuscation, and brand mismatches.
2. **`ThreatIntelligenceAgent`:** Checks local threat intelligence feeds, known malware patterns (e.g. Google Safe Browsing test malware paths), and threat signatures.
3. **`DomainIntelligenceAgent`:** Validates domain anchors against the Tranco Top 100K whitelist and official banking domain registries (`sbi.co.in`, `hdfcbank.com`, `icicibank.com`, etc.).
4. **`HTTPSCertificateAgent`:** Evaluates transport layer security. Strictly enforces that **HTTPS encryption != site legitimacy** to eliminate false-negative security assumptions.
5. **`WebsiteContentAgent`:** Analyzes website and message copy for credential harvesting forms, OTP demands, and coercive suspension threats.
6. **`BehavioralRedirectAgent`:** Detects shortener bounce concealments, redirect loops (>5 hops), and cross-origin jumps.
7. **`CommunityReputationAgent`:** Evaluates crowdsourced threat reports and community flagging weighted by trust anchors.
8. **`IndianScamIntelligenceAgent`:** Specialized pattern matching for high-impact Indian fraud vectors (Digital Arrest, Electricity disconnection, UPI PIN fraud, India Post fee).

### Evidence-Based Main Orchestrator
The Main Orchestrator resolves contradictions across agents (e.g., Transport Security Contradiction: site has valid SSL but is a known phishing kit) and emits structured, typed verdicts:
- `CONFIRMED_MALICIOUS` (Risk: 95-100%)
- `HIGH_RISK` (Risk: 75-94%)
- `SUSPICIOUS` (Risk: 40-74%)
- `UNVERIFIED` (Risk: 20-39%)
- `NO_KNOWN_THREAT` / `VERIFIED_TRUSTED` (Risk: 0-15%)

---

## 6. CLI Command Reference (`scamshield-ml`)

The CLI is powered by `Typer` and `Rich` and can be invoked either from the repository root (`uv run scamshield-ml <command>`) or from inside `ml-lab/`:

| Command | Description |
|---|---|
| `scamshield-ml status` | Display overall lab progress, dataset metrics, trained models, and next actions. |
| `scamshield-ml progress` | Show detailed ASCII/Rich progress bars across all 12 pipeline phases. |
| `scamshield-ml todo` | Show pending, in-progress, and completed pipeline items. |
| `scamshield-ml dataset collect` | Collect and ingest raw multilingual security samples into `data/raw/`. |
| `scamshield-ml dataset preprocess` | Run Unicode NFC normalization and sanitization into `data/processed/`. |
| `scamshield-ml dataset validate` | Execute deduplication, Jaccard near-duplicate check, and zero-leakage split. |
| `scamshield-ml dataset stats` | Display language and threat category distribution tables. |
| `scamshield-ml dataset audit` | Render the complete Markdown dataset audit report. |
| `scamshield-ml train <model>` | Train a specific model (`logistic`, `knn`, `ann`, `url`, `ensemble`). |
| `scamshield-ml train ann --resume` | Resume ANN training from the last saved epoch checkpoint. |
| `scamshield-ml experiment run-all` | Run the complete pipeline end-to-end, evaluate on test split, and generate leaderboard. |
| `scamshield-ml leaderboard` | Display the held-out test split leaderboard ranking. |
| `scamshield-ml export-best` | Export the #1 ranked model to `artifacts/models/best_model.joblib`. |
| `scamshield-ml analyze <text>` | Run full ensemble + multi-agent threat analysis on a message. |
| `scamshield-ml analyze-url <url>` | Run sandbox URL analysis with contradiction detection and threat feeds. |
| `scamshield-ml serve --port 8000` | Launch the FastAPI high-throughput REST inference server. |
| `scamshield-ml verify` | Execute the complete automated pytest verification suite. |

---

## 7. REST Inference API

Launch the server:
```bash
uv run scamshield-ml serve --port 8000
```

### Endpoints:
- **`GET /health`**: Health status, uptime, and state database connectivity.
- **`GET /api/v1/models/status`**: Current loaded models, active best model, and experiment summary.
- **`POST /api/v1/analyze`**: Threat analysis endpoint. Accepts `{ "message": "...", "url": "...", "source": "whatsapp" }`.

---

## 8. Verification & Testing

Run the test suite:
```bash
cd ml-lab && uv run pytest tests/ -v
```

All 24 unit and integration tests pass:
- `tests/test_state.py` (5 tests): State persistence, 12 phases, active job leases, experiment logging.
- `tests/test_dataset.py` (3 tests): Ingestion, NFC normalization, deduplication, zero data leakage.
- `tests/test_models.py` (5 tests): Logistic Regression, KNN, ANN checkpointing, URL Classifier, Soft-Voting Ensemble.
- `tests/test_agents.py` (6 tests): All 8 threat intelligence agents, contradiction resolution, typed verdicts.
- `tests/test_inference.py` (5 tests): Healthcheck, model status, message analysis, URL analysis, validation error handling.
