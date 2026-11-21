# ScamShield Dataset Quality & Leakage Audit Report

- **Dataset Name:** ScamShield-IndiaFirst-Cybersecurity-Benchmark
- **Version:** `v1.0.0-07e9087db727`
- **Dataset Hash:** `07e9087db727`
- **Total Unique Samples:** 138
- **Raw Inputs Processed:** 138
- **Duplicates Purged:** 0
- **Near-Duplicate Pairs Flagged:** 5
- **Data Leakage Check:** PASSED (Zero Overlap)

---

## 1. Split Distribution
| Split | Sample Count | Percentage |
|---|---|---|
| **Train** | 91 | 65.9% |
| **Validation** | 19 | 13.8% |
| **Test** | 28 | 20.3% |

---

## 2. Class Distribution
| Class | Count | Ratio |
|---|---|---|
| **Scam / Malicious (1)** | 95 | 68.8% |
| **Legitimate (0)** | 43 | 31.2% |

---

## 3. Language Diversity Breakdown
| Language | Samples | Ratio |
|---|---|---|
| `en` | 101 | 73.2% |
| `hinglish` | 17 | 12.3% |
| `hi` | 8 | 5.8% |
| `mr` | 11 | 8.0% |
| `romanized_mr` | 1 | 0.7% |

---

## 4. Threat Category Breakdown
| Category | Count |
|---|---|
| `BANKING_KYC` | 21 |
| `UPI_FRAUD` | 11 |
| `ELECTRICITY` | 11 |
| `DELIVERY` | 7 |
| `LOTTERY` | 7 |
| `JOB_OFFER` | 6 |
| `DIGITAL_ARREST` | 7 |
| `OTP_THEFT` | 5 |
| `LEGITIMATE` | 43 |
| `PHISHING_URL` | 20 |

---

## 5. Leakage Prevention Verification
- Exact matches between Train and Test: **0**
- Exact matches between Train and Val: **0**
- Exact matches between Val and Test: **0**
- Hash verification algorithm: `SHA-256` content hashing
