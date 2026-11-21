# ScamShield Dataset Quality & Leakage Audit Report

- **Dataset Name:** ScamShield-IndiaFirst-Cybersecurity-Benchmark
- **Version:** `v2.0.0-ca6930eccd7f`
- **Dataset Hash:** `ca6930eccd7f`
- **Total Unique Samples:** 343
- **Raw Inputs Processed:** 345
- **Duplicates Purged:** 2
- **Near-Duplicate Pairs Flagged:** 0
- **Data Leakage Check:** PASSED (Zero Overlap)

---

## 1. Split Distribution
| Split | Sample Count | Percentage |
|---|---|---|
| **Train** | 231 | 67.3% |
| **Validation** | 52 | 15.2% |
| **Test** | 60 | 17.5% |

---

## 2. Class Distribution
| Class | Count | Ratio |
|---|---|---|
| **Scam / Malicious (1)** | 187 | 54.5% |
| **Legitimate (0)** | 156 | 45.5% |

---

## 3. Language Diversity Breakdown
| Language | Samples | Ratio |
|---|---|---|
| `en` | 244 | 71.1% |
| `hinglish` | 37 | 10.8% |
| `hi` | 26 | 7.6% |
| `mr` | 34 | 9.9% |
| `romanized_mr` | 2 | 0.6% |

---

## 4. Threat Category Breakdown
| Category | Count |
|---|---|
| `BANKING_KYC` | 27 |
| `UPI_FRAUD` | 19 |
| `ELECTRICITY` | 16 |
| `DELIVERY` | 14 |
| `LOTTERY` | 6 |
| `JOB_OFFER` | 13 |
| `DIGITAL_ARREST` | 14 |
| `OTP_THEFT` | 4 |
| `LEGITIMATE` | 156 |
| `PHISHING_URL` | 43 |
| `LOAN_FRAUD` | 5 |
| `REMOTE_ACCESS_FRAUD` | 5 |
| `SIM_DEACTIVATION` | 6 |
| `TAX_CHALLAN_FRAUD` | 5 |
| `CUSTOMER_SUPPORT_SCAM` | 4 |
| `EVASION_PERTURBATION` | 6 |

---

## 5. Leakage Prevention Verification
- Exact matches between Train and Test: **0**
- Exact matches between Train and Val: **0**
- Exact matches between Val and Test: **0**
- Domain overlap between Train and Test: **0** (Cluster-aware split)
- Hash verification algorithm: `SHA-256` content hashing
