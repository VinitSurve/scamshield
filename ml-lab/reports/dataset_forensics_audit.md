# Forensic Dataset Audit Report: ScamShield-IndiaFirst-Cybersecurity-Benchmark

- **Audit Date:** 2026-11-22
- **Target Dataset:** `ml-lab/data/raw/raw_dataset.json`
- **Processed Splits:** `ml-lab/data/processed/train.json`, `val.json`, `test.json`
- **Total Samples Audited:** 138 (Train: 91, Val: 19, Test: 28)
- **Dataset Hash:** `07e9087db727`
- **Auditor:** Forensic ML Audit Agent (Agent A)
- **Audience:** Orchestrator, Agent B (Dataset Expansion), Agent C (URL Dataset)

---

## Executive Summary

A forensic quality, integrity, and data leakage audit was conducted across the raw dataset and processed splits (`train.json`, `val.json`, `test.json`) of the **ScamShield-IndiaFirst-Cybersecurity-Benchmark**. 

While the baseline pipeline reported zero exact SHA-256 hash collisions across splits, a deeper forensic examination revealed **critical methodological vulnerabilities, severe data leakage, artificial sample cloning, and acute demographic skews** that invalidate current performance metrics:

1. **Test Split Label Distortion:** The test set exhibits a severe 3:1 label imbalance (75.0% scam vs. 25.0% legitimate), containing only 7 legitimate samples. False positive rate (FPR) estimation on this test set is statistically unviable (a single mistake swings FPR by 14.3%).
2. **Cross-Split Near-Duplicate Leakage:** Out of 11 near-duplicate pairs (Jaccard similarity $\ge 0.80$ on character 3-grams), **9 pairs cross split boundaries** (6 Train–Test, 2 Train–Val, 1 Val–Test). More than **21.4% of the test set** (6 of 28 samples) are syntactic clones of training set messages.
3. **Severe Domain Leakage:** Out of 13 URL-bearing samples in the test set, **6 samples (46.15%) share exact domains with training samples**. Models evaluated on this split memorize domain names rather than learning generalizable phishing signals.
4. **Synthetic Template Cloning & Entity Reuse:** Samples `SCAM-DATA-00127` through `SCAM-DATA-00138` were mechanically cloned from earlier samples by merely swapping dummy phone numbers (`9876543210` $\rightarrow$ `9123456789`) or financial amounts. Four dummy phone numbers account for 22 samples across 7 threat categories.
5. **Critical Category Underrepresentation:** 5 out of 10 threat categories have fewer than 10 samples total (`OTP_THEFT`: 5, `JOB_OFFER`: 6, `DELIVERY`: 7, `LOTTERY`: 7, `DIGITAL_ARREST`: 7). In the test set, `JOB_OFFER` and `OTP_THEFT` have only 1 sample each.
6. **Severe Language Skew:** Despite ScamShield's "India-First" mission, **73.2% of samples are in English**. `romanized_mr` is an orphan class with only 1 sample (present in Val, 0 in Train, 0 in Test). Hindi has only 8 samples total, and the sole Hindi test sample is a clone of a train sample (zero unseen Hindi evaluation samples).
7. **RFC 1918 Private IP Misclassification:** Sample `SCAM-DATA-00114` labels a local home router admin IP (`http://192.168.1.1/admin/login.php`) as `PHISHING_URL`.

---

## 1. Label Imbalance Analysis

### 1.1 Class Distribution Per Split

The dataset exhibits notable class imbalance across all splits, culminating in an extreme skew in the test partition:

| Partition | Total Samples | Scam Count (`is_scam=1`) | Legit Count (`is_scam=0`) | Scam Ratio | Legit Ratio | Scam-to-Legit Ratio |
|---|---|---|---|---|---|---|
| **Raw Dataset** | 138 | 95 | 43 | 68.84% | 31.16% | **2.21 : 1** |
| **Train Split** | 91 | 61 | 30 | 67.03% | 32.97% | **2.03 : 1** |
| **Val Split** | 19 | 13 | 6 | 68.42% | 31.58% | **2.17 : 1** |
| **Test Split** | 28 | 21 | 7 | 75.00% | 25.00% | **3.00 : 1** |

### 1.2 Forensic Impact on Evaluation
- **High Sensitivity to False Positives:** With only **7 legitimate samples** in `test.json`, each legitimate message carries a statistical weight of **14.29%**. A classifier that misclassifies two legitimate messages receives an apparent FPR of 28.57%, while misclassifying none reports an artificially clean 0.0% FPR.
- **Accuracy Metric Distortion:** A naive dummy classifier predicting `scam` for every input achieves **75.0% accuracy** on the test partition without learning any discrimination boundary.
- **Recommendation:** Rebalance the benchmark splits so the test set has at least a **1:1** or **1.5:1** balance with a minimum of 200–500 legitimate Indian communication samples.

---

## 2. Exact Duplicate Hashes & Near-Duplicate Analysis

### 2.1 Exact Hash Verification
- **Raw Dataset SHA-256 Uniqueness:** 138 unique hashes out of 138 entries.
- **Normalized SHA-256 Uniqueness:** 138 unique normalized hashes (after lowercasing and whitespace collapse).
- **Exact Hash Overlap Between Splits:**
  - Train $\cap$ Val: **0**
  - Train $\cap$ Test: **0**
  - Val $\cap$ Test: **0**

While exact hash deduplication succeeded in preventing bit-for-bit duplicate files from entering multiple splits, it acted as a blind spot for trivial syntactic mutations.

### 2.2 Character 3-Gram Jaccard Near-Duplicate Audit

A pairwise audit across all 138 samples was executed using character 3-gram Jaccard similarity:
$$\text{Jaccard}(S_1, S_2) = \frac{|N_3(S_1) \cap N_3(S_2)|}{|N_3(S_1) \cup N_3(S_2)|}$$
where $N_3(S)$ denotes the set of whitespace-stripped character 3-grams of string $S$.

At threshold $\ge 0.80$, **11 near-duplicate pairs** were identified:
- **Same-Split Pairs:** 2 (both in Train)
- **Cross-Split Leakage Pairs:** **9 pairs** (6 Train–Test, 2 Train–Val, 1 Val–Test)

### 2.3 Inventory of Cross-Split Near-Duplicate Leakage

| Pair ID | Split 1 (ID & Cat) | Split 2 (ID & Cat) | Jaccard Sim | Content Difference Analysis |
|---|---|---|---|---|
| **ND-01** | **TRAIN** (`SCAM-DATA-00063`, LEGITIMATE) | **TEST** (`SCAM-DATA-00137`, LEGITIMATE) | **0.9304** | SBI NEFT salary credit. Identical except amount changed from `Rs 45,000` to `Rs 52,000`. |
| **ND-02** | **TRAIN** (`SCAM-DATA-00138`, LEGITIMATE) | **VAL** (`SCAM-DATA-00066`, LEGITIMATE) | **0.9123** | Mahavitaran electricity bill. Identical consumer #`10293847`, differing only in amount (`Rs 1,120` vs `Rs 850`). |
| **ND-03** | **VAL** (`SCAM-DATA-00135`, DIGITAL_ARREST) | **TEST** (`SCAM-DATA-00052`, DIGITAL_ARREST) | **0.9079** | Mumbai Cyber Crime narcotic parcel warrant. Identical except phone number (`+91 9123456789` vs `+91 9876543210`). |
| **ND-04** | **TRAIN** (`SCAM-DATA-00128`, BANKING_KYC) | **TEST** (`SCAM-DATA-00004`, BANKING_KYC) | **0.9068** | Hinglish SBI KYC phishing. "State Bank" vs "SBI", identical URL `https://sbi-kyc-alert.top/pan`. |
| **ND-05** | **TRAIN** (`SCAM-DATA-00011`, BANKING_KYC) | **TEST** (`SCAM-DATA-00130`, BANKING_KYC) | **0.8962** | YONO reward points expiry scam. "YONO SBI" vs "YONO State Bank", identical URL `https://sbi-yono-reward.top`. |
| **ND-06** | **TRAIN** (`SCAM-DATA-00136`, OTP_THEFT) | **VAL** (`SCAM-DATA-00058`, OTP_THEFT) | **0.8701** | IP `185.220.101.4` login alert. Identical text and IP, differing only in callback phone (`9123456789` vs `9876543210`). |
| **ND-07** | **TRAIN** (`SCAM-DATA-00132`, ELECTRICITY) | **TEST** (`SCAM-DATA-00030`, ELECTRICITY) | **0.8525** | Hindi power cut notification. Identical phrasing, differing only in phone number (`9123456789` vs `9876543210`). |
| **ND-08** | **TRAIN** (`SCAM-DATA-00129`, BANKING_KYC) | **TEST** (`SCAM-DATA-00009`, BANKING_KYC) | **0.8407** | Axis Bank deactivation notice. Identical URL `https://axis-online-kyc.top`, differing only in phone (`919123456789` vs `919876543210`). |
| **ND-09** | **TRAIN** (`SCAM-DATA-00048`, JOB_OFFER) | **TEST** (`SCAM-DATA-00134`, JOB_OFFER) | **0.8235** | Hinglish YouTube like/review job scam. Identical phrasing, differing only in WhatsApp phone (`9876543210` vs `9123456789`). |
| *Borderline* | **TRAIN** (`SCAM-DATA-00127`, BANKING_KYC) | **TEST** (`SCAM-DATA-00001`, BANKING_KYC) | **0.7973** | SBI KYC account blocked. "State Bank" vs "SBI", identical URL `https://sbi-online-kyc.top/verify`, phone changed (`9123456789` vs `9876543210`). |

### 2.4 Same-Split Near-Duplicates (Redundancy in Train)
1. `SCAM-DATA-00131` vs `SCAM-DATA-00026` in **TRAIN** (Jaccard: **0.8658**, `ELECTRICITY`): English power cut warning, differing only in officer phone number.
2. `SCAM-DATA-00133` vs `SCAM-DATA-00042` in **TRAIN** (Jaccard: **0.8254**, `LOTTERY`): Hinglish KBC 25 Lakh prize scam, differing only in WhatsApp phone number.

### 2.5 Audit Finding
**21.4% (6 of 28) of the test samples are near-exact duplicates of training set messages.** Models trained on `train.json` achieve artificially high test scores simply by recognizing verbatim phrases and identical links seen during training.

---

## 3. Data Leakage and Domain Overlap

### 3.1 Domain Inventory Per Split
Extracting all domains and hostnames from `extracted_urls` and message body URLs yielded:
- **Unique Domains in Train:** 44
- **Unique Domains in Val:** 12
- **Unique Domains in Test:** 13

### 3.2 Cross-Split Domain Overlap
- **Train $\cap$ Test Domain Overlap:** **6 domains**
- **Train $\cap$ Val Domain Overlap:** **4 domains**
- **Val $\cap$ Test Domain Overlap:** **3 domains**

### 3.3 Detailed Breakdown of Train–Test Leaked Domains

| Leaked Domain | Split Occurrences & Sample IDs | Category | Threat Verdict |
|---|---|---|---|
| `amazon-lucky-gift.top` | Train: `SCAM-DATA-00046` (message)<br>Test: `SCAM-DATA-00120` (bare URL) | `LOTTERY` / `PHISHING_URL` | Malicious |
| `axis-online-kyc.top` | Train: `SCAM-DATA-00129` (message)<br>Test: `SCAM-DATA-00009` (message) | `BANKING_KYC` | Malicious |
| `mahadiscom.in` | Train: `SCAM-DATA-00138` (message)<br>Test: `SCAM-DATA-00091` (bare URL) | `LEGITIMATE` | Legitimate |
| `sbi-kyc-alert.top` | Train: `SCAM-DATA-00128` (message)<br>Test: `SCAM-DATA-00004` (message) | `BANKING_KYC` | Malicious |
| `sbi-online-kyc.top` | Train: `SCAM-DATA-00127` (message)<br>Test: `SCAM-DATA-00001` (message) | `BANKING_KYC` | Malicious |
| `sbi-yono-reward.top` | Train: `SCAM-DATA-00011` (message)<br>Test: `SCAM-DATA-00130` (message) | `BANKING_KYC` | Malicious |

### 3.4 Impact on URL Classifier Evaluation
- **Total URL-bearing samples in Test:** 13
- **Test samples containing Train-leaked domains:** **6 out of 13 (46.15%)**
- **Cross-Modal Contamination:** The benchmark contains bare URLs (`content_type: url`) in the test split whose parent domains were already exposed in conversational messages (`content_type: message`) in the training split (e.g., `amazon-lucky-gift.top` in `SCAM-DATA-00046` vs `SCAM-DATA-00120`). Any feature extractor or embedding model that extracts hostnames or subdomains directly transfers learned weights into test performance.

---

## 4. Missing Fields and Schema Non-Conformance

### 4.1 Schema Validation Check Against `datasets/schema.json`
Every sample in `raw_dataset.json`, `train.json`, `val.json`, and `test.json` conforms to the core schema requirements:
- Required fields (`sample_id`, `content`, `content_type`, `label`, `is_scam`, `category`, `language`): **100% present (0 missing)**.
- `label` vs `is_scam` alignment: **100% consistent** (`scam` $\iff 1$, `legitimate` $\iff 0$).
- Extracted entity types: `extracted_urls`, `extracted_phones`, and `extracted_upis` are all valid lists.

### 4.2 Pipeline Field Inconsistency
While schema validation passes, the schema lacks strict definitions for metadata injected along the pipeline:
1. `raw_dataset.json` contains 11 fields.
2. `clean_dataset.json` introduces `char_length` and `word_count` (13 fields).
3. `train.json`, `val.json`, and `test.json` introduce `sha256` (14 fields).
`ml-lab/datasets/schema.json` does not declare `additionalProperties: false`, allowing undocumented pipeline fields without validation.

### 4.3 Ground Truth Label & Extraction Deficiencies
1. **RFC 1918 Private IP Misclassified as Phishing (`SCAM-DATA-00114`):**
   - Sample content: `http://192.168.1.1/admin/login.php`
   - Label: `scam`, Category: `PHISHING_URL`
   - **Flaw:** `192.168.1.1` is a private, non-routable IPv4 address reserved by IANA for local gateway devices. An internal network admin panel is not a phishing attack. Penalizing private IP traffic as phishing risks generating false positives on legitimate intranet systems.
2. **Trailing Punctuation in URL Extraction:**
   - In `SCAM-DATA-00003` (`...at https://hdfc-bank-verify.xyz/auth.`) and `SCAM-DATA-00062` (`...at https://bluedart.com/track/4029982141.`), trailing sentence periods were stripped in `extracted_urls` but remain embedded in the raw content string, leading to tokenization mismatches in naive regex extractors.

---

## 5. Language Representation Distribution

### 5.1 Linguistic Breakdown Across Splits

| Language Code | Description | Raw Count (%) | Train Count (%) | Val Count (%) | Test Count (%) |
|---|---|---|---|---|---|
| `en` | English | 101 (73.19%) | 66 (72.53%) | 14 (73.68%) | 21 (75.00%) |
| `hinglish` | Hindi-English code-mixed | 17 (12.32%) | 13 (14.29%) | 1 (5.26%) | 3 (10.71%) |
| `mr` | Marathi (Devanagari script) | 11 (7.97%) | 6 (6.59%) | 2 (10.53%) | 3 (10.71%) |
| `hi` | Hindi (Devanagari script) | 8 (5.80%) | 6 (6.59%) | 1 (5.26%) | 1 (3.57%) |
| `romanized_mr`| Marathi in Latin script | 1 (0.72%) | **0 (0.00%)** | 1 (5.26%) | **0 (0.00%)** |
| **Total** | | **138** | **91** | **19** | **28** |

### 5.2 Critical Linguistic Deficiencies
1. **The "India-First" Paradox:** While marketed as an "India-First Cybersecurity Benchmark", **73.2% of the dataset is standard English**. Real-world Indian cyber fraud predominantly targets tier-2 and tier-3 users through vernacular SMS, WhatsApp voice notes, and Romanized regional phrasing.
2. **Orphan Language Class (`romanized_mr`):** There is exactly **1 sample** of Romanized Marathi in the entire dataset (`SCAM-DATA-00008` in `val.json`). It is absent from `train.json` (models cannot train on it) and absent from `test.json` (models cannot be tested on it).
3. **Severe Hindi Starvation:** Hindi has only 8 samples in the entire dataset. In `test.json`, there is only **1 Hindi sample** (`SCAM-DATA-00030`), which is an exact clone of Train sample `SCAM-DATA-00132`. Therefore, the benchmark contains **zero unseen Hindi test samples**.

---

## 6. Category Representation Distribution

### 6.1 Threat Category Breakdown

Five of the ten threat categories (50%) have fewer than 10 samples in the entire dataset:

| Threat Category | Raw Total | Train | Val | Test | Underrepresented Flag | Test Sample IDs |
|---|---|---|---|---|---|---|
| `LEGITIMATE` | 43 | 30 | 6 | 7 | Adequate | `00072`, `00075`, `00084`, `00085`, `00091`, `00126`, `00137` |
| `BANKING_KYC` | 21 | 14 | 3 | 4 | Adequate | `00001`, `00004`, `00009`, `00130` |
| `PHISHING_URL` | 20 | 14 | 3 | 3 | Adequate | `00114`, `00115`, `00120` |
| `ELECTRICITY` | 11 | 7 | 1 | 3 | Adequate | `00030`, `00031`, `00032` |
| `UPI_FRAUD` | 11 | 7 | 1 | 3 | Adequate | `00019`, `00024`, `00125` |
| `DELIVERY` | 7 | 4 | 1 | 2 | **CRITICAL (< 10)** | `00036`, `00040` |
| `LOTTERY` | 7 | 4 | 1 | 2 | **CRITICAL (< 10)** | `00041`, `00045` |
| `DIGITAL_ARREST` | 7 | 4 | 1 | 2 | **CRITICAL (< 10)** | `00052`, `00057` |
| `JOB_OFFER` | 6 | 4 | 1 | 1 | **CRITICAL (< 10)** | `00134` (near-clone of train `00048`) |
| `OTP_THEFT` | 5 | 3 | 1 | 1 | **CRITICAL (< 10)** | `00059` |

### 6.2 Forensic Analysis of Category Representation
- **Single-Sample Test Categories:** Both `JOB_OFFER` and `OTP_THEFT` are evaluated on exactly **one sample** in `test.json`. For `JOB_OFFER`, that sole sample is a clone of a training sample. A single error on `OTP_THEFT` drops test recall for that category to 0.0%.
- **Validation Split Fragility:** In `val.json`, **7 of 10 categories have exactly 1 sample** (`DELIVERY`, `DIGITAL_ARREST`, `ELECTRICITY`, `JOB_OFFER`, `LOTTERY`, `OTP_THEFT`, `UPI_FRAUD`). Hyperparameter search or early stopping guided by this validation set is unstable and prone to high-variance overfitting.

---

## 7. Weak Sample Diversity and Template Repetition

### 7.1 Synthetic Template Cloning (`SCAM-DATA-00127` – `00138`)
Samples `00127` through `00138` were created by applying single-slot variable substitution to existing samples:
- `SCAM-DATA-00001` $\rightarrow$ `SCAM-DATA-00127`: Replaced "SBI" with "State Bank", swapped phone number.
- `SCAM-DATA-00004` $\rightarrow$ `SCAM-DATA-00128`: Replaced "SBI" with "State Bank", kept identical URL.
- `SCAM-DATA-00009` $\rightarrow$ `SCAM-DATA-00129`: Kept identical text and URL, changed phone number.
- `SCAM-DATA-00011` $\rightarrow$ `SCAM-DATA-00130`: Replaced "YONO SBI" with "YONO State Bank", kept identical URL.
- `SCAM-DATA-00026` $\rightarrow$ `SCAM-DATA-00131`: Kept identical text, changed officer phone number.
- `SCAM-DATA-00030` $\rightarrow$ `SCAM-DATA-00132`: Kept identical Hindi text, changed phone number.
- `SCAM-DATA-00042` $\rightarrow$ `SCAM-DATA-00133`: Kept identical KBC text, changed phone number.
- `SCAM-DATA-00048` $\rightarrow$ `SCAM-DATA-00134`: Kept identical YouTube job text, changed phone number.
- `SCAM-DATA-00052` $\rightarrow$ `SCAM-DATA-00135`: Kept identical Mumbai Police notice, changed phone number.
- `SCAM-DATA-00058` $\rightarrow$ `SCAM-DATA-00136`: Kept identical IP address and text, changed phone number.
- `SCAM-DATA-00063` $\rightarrow$ `SCAM-DATA-00137`: Kept identical salary alert, changed amount from Rs 45,000 to Rs 52,000.
- `SCAM-DATA-00066` $\rightarrow$ `SCAM-DATA-00138`: Kept identical Mahavitaran bill, changed amount from Rs 850 to Rs 1,120.

### 7.2 Entity Repetition Across Samples
The dataset exhibits extreme reuse of placeholder phone numbers and UPI IDs:
- **Phone `9123456789`:** Reused across **10 samples** spanning 7 categories.
- **Phone `9876543210`:** Reused across **5 samples**.
- **Phone `+91 9876543210`:** Reused across **3 samples**.
- **Phone `9811223344`:** Reused across **4 samples**.
- **UPI `refund-desk@upi`:** Reused across **2 samples**.
- **Shortener `is.gd`:** Reused across **4 samples**.

In total, **22 out of 138 samples (15.9%)** share the same 4 phone numbers. Models risk learning associative weights on these dummy numbers rather than scam intent.

### 7.3 Lexical Diversity Metrics
- **Total Word Count:** 2,843 words
- **Unique Vocabulary:** 824 tokens
- **Type-Token Ratio (TTR):** **0.2898** (extremely low linguistic diversity for a multi-category corpus)
- **Bare URLs as Samples:** 40 samples (29.0%) are bare URLs (`content_type: url`) containing no text, reducing the effective conversational message training set to just 98 samples.

---

## 8. Actionable Recommendations

### 8.1 Directives for Agent B (Dataset Expansion)

Agent B is tasked with expanding the conversational message dataset from 138 samples to a production-grade benchmark.

1. **Target Scale & Quota Structure:**
   - Expand total samples from 138 to **at least 1,500 – 2,500 curated samples**.
   - Maintain a 1:1 or 1.2:1 ratio of Scam to Legitimate samples across all splits.
2. **Strict Linguistic Quotas:**
   - Cap standard English at **35% - 40%**.
   - Mandate Indic representation:
     - **Hinglish:** 25% (realistic everyday conversational code-mixing)
     - **Hindi (Devanagari):** 15% ($\ge 300$ samples)
     - **Marathi (Devanagari):** 15% ($\ge 300$ samples)
     - **Romanized Marathi (`romanized_mr`):** 5% ($\ge 100$ samples)
     - Optional extensions: Romanized Hindi, Tamil, Telugu, Kannada.
3. **Rebalancing Underrepresented Threat Categories:**
   - Expand every threat category with $< 10$ samples to **at least 120 – 150 samples**:
     - `OTP_THEFT`: 150+ samples covering diverse banking, e-commerce, and delivery OTP theft angles.
     - `JOB_OFFER`: 150+ samples covering Part-Time Telegram, YouTube liking, hotel rating, and data entry scams.
     - `DELIVERY`: 150+ samples covering India Post, DTDC, BlueDart, Delhivery customs and address hold scams.
     - `LOTTERY`: 150+ samples covering KBC, Amazon lucky draw, Diwali bumper, and cryptocurrency giveaways.
     - `DIGITAL_ARREST`: 150+ samples covering CBI, ED, Mumbai Police, FedEx customs drug parcel coercion.
4. **Legitimate Class Diversity:**
   - Synthesize and curate authentic Indian transactional alerts:
     - Banking: NEFT, IMPS, RTGS, UPI debits/credits from SBI, HDFC, ICICI, Axis, PNB, BoB.
     - Utilities: Bill reminders, receipts, and outages from Mahavitaran, Adani Electricity, BESCOM, Tata Power, IGL, Mahanagar Gas.
     - E-commerce & Delivery: Shipping, delivery OTP, return confirmations from Swiggy, Zomato, Amazon, Flipkart, Blinkit, Zepto.
     - Government Services: DigiLocker, Aadhaar update, Income Tax return processing, FASTag recharge alerts.
5. **Elimination of Single-Slot Mutation & Entity Diversity:**
   - Prohibit copy-paste mutations of existing samples where only numbers are modified.
   - Use dynamic entity generators with real-world Indian names, diverse phone prefixes (`+91 98`, `+91 97`, `+91 88`, `+91 70`, etc.), valid UPI handles (`@okaxis`, `@oksbi`, `@paytm`, `@ybl`, `@axl`), and state-specific terminology.
6. **Grouped / Cluster-Based Stratified Splitting:**
   - Replace naive random/stratified splitting with **Cluster-Aware Group Splitting**.
   - Group near-duplicate messages (Jaccard similarity $\ge 0.65$) into clusters and assign the entire cluster strictly to a single split (Train, Val, or Test).

---

### 8.2 Directives for Agent C (URL Dataset)

Agent C is tasked with developing and curating the dedicated URL detection dataset and benchmark.

1. **Decouple URL Dataset from Message Corpus:**
   - Fully separate bare URL evaluation from conversational message evaluation.
   - The message corpus should contain URLs only as natural embedded entities within messages.
2. **Strict Domain-Level Split Isolation:**
   - Enforce **Zero-Domain-Overlap** between Train, Val, and Test splits.
   - Group URLs by **registrable domain** (e.g., `sbi-online-kyc.top` or `axis-bank.top`) and allocate all paths/subdomains of a domain exclusively to one split.
   - Test set evaluation must measure zero-day domain generalization, not known-domain memorization.
3. **Scale and Source Composition:**
   - Scale URL dataset from 40 to **5,000 – 10,000 unique URLs**.
   - **Malicious Sources:**
     - OpenPhish, PhishTank, URLhaus, APWG feeds filtered for Indian banking, UPI, telecom (Airtel, Jio, Vi), and government imposter attacks.
   - **Legitimate Sources:**
     - Tranco Top 10k, with heavy sampling of Indian domains (`.gov.in`, `.nic.in`, `.ac.in`, `.res.in`, `.co.in`, `.bank.in`).
4. **Purge RFC 1918 Private Addresses:**
   - Remove `192.168.1.1` and all RFC 1918 (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) or loopback (`127.0.0.1`) addresses from the phishing category.
   - IP-literal phishing samples must only include public, non-reserved routable IPs.
5. **Multi-Vector Phishing Feature Coverage:**
   - Ensure balanced representation of advanced phishing techniques:
     - IDN / Punycode homoglyph attacks (e.g., `xn--...`).
     - Subdomain spoofing (`sbi.co.in.fake-portal.com`).
     - URL shorteners (`bit.ly`, `tinyurl`, `is.gd`, `t.co`).
     - High-risk disposable TLDs (`.top`, `.xyz`, `.club`, `.site`, `.online`, `.live`).
     - Path-based obfuscation and credential harvest paths (`/verify/pan`, `/auth/login.php`).

---

## 9. Summary Scorecard

| Forensic Audit Dimension | Status | Severity | Primary Finding |
|---|---|---|---|
| **Class Balance** | **FAILED** | **HIGH** | Test split has 3:1 scam skew with only 7 legitimate samples; FPR estimation is invalid. |
| **Deduplication** | **FAILED** | **CRITICAL** | 9 cross-split near-duplicate pairs (Jaccard $\ge 0.80$); 21.4% of test set leaked from train. |
| **Domain Leakage** | **FAILED** | **CRITICAL** | 6 of 13 URL-bearing test samples (46.15%) share exact domains with training set. |
| **Schema Integrity** | **PASS WITH WARNING** | **LOW** | 100% schema conformance; undocumented pipeline fields (`sha256`) and mislabeled RFC 1918 IP. |
| **Linguistic Balance** | **FAILED** | **HIGH** | 73.2% English; `romanized_mr` has 1 sample (0 in train/test); 0 unseen Hindi test samples. |
| **Category Coverage** | **FAILED** | **HIGH** | 5 of 10 categories have $< 10$ samples; `JOB_OFFER` and `OTP_THEFT` have 1 test sample each. |
| **Sample Diversity** | **FAILED** | **MEDIUM** | 12 synthetically cloned samples (`00127`-`00138`); 4 phone numbers repeated across 22 samples. |

---
*Report generated and signed by Forensic ML Audit Agent (Agent A).*
