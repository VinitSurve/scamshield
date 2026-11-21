# ScamShield Dataset Quality & Leakage Audit Report

- **Dataset Name:** ScamShield-IndiaFirst-Cybersecurity-Benchmark
- **Version:** `v3.0.0-f69bd734516c`
- **Dataset Hash:** `f69bd734516c`
- **Total Unique Samples:** 2190
- **Raw Inputs Processed:** 2190
- **Duplicates Purged:** 0
- **Near-Duplicate Pairs Flagged:** 1545
- **Data Leakage Check:** PASSED (Zero Overlap)

---

## 1. Split Distribution
| Split | Sample Count | Percentage |
|---|---|---|
| **Train** | 1361 | 62.1% |
| **Validation** | 537 | 24.5% |
| **Test** | 292 | 13.3% |

---

## 2. Class Distribution
| Class | Count | Ratio |
|---|---|---|
| **Scam / Malicious (1)** | 1128 | 51.5% |
| **Legitimate (0)** | 1062 | 48.5% |

---

## 3. Language Diversity Breakdown
| Language | Samples | Ratio |
|---|---|---|
| `en` | 1146 | 52.3% |
| `hinglish` | 261 | 11.9% |
| `hi` | 378 | 17.3% |
| `mr` | 315 | 14.4% |
| `romanized_mr` | 90 | 4.1% |

---

## 4. Threat Category Breakdown
| Category | Count |
|---|---|
| `BANKING_KYC` | 231 |
| `UPI_FRAUD` | 53 |
| `ELECTRICITY` | 126 |
| `DELIVERY` | 74 |
| `LOTTERY` | 30 |
| `JOB_OFFER` | 85 |
| `DIGITAL_ARREST` | 90 |
| `OTP_THEFT` | 54 |
| `LEGITIMATE` | 156 |
| `PHISHING_URL` | 63 |
| `LOAN_FRAUD` | 53 |
| `REMOTE_ACCESS_FRAUD` | 29 |
| `SIM_DEACTIVATION` | 54 |
| `TAX_CHALLAN_FRAUD` | 21 |
| `CUSTOMER_SUPPORT_SCAM` | 24 |
| `EVASION_PERTURBATION` | 6 |
| `LEGITIMATE_BANKING` | 254 |
| `LEGITIMATE_UPI` | 192 |
| `LEGITIMATE_OTP` | 300 |
| `LEGITIMATE_KYC` | 48 |
| `LEGITIMATE_GOVT_ADVISORY` | 13 |
| `LEGITIMATE_UTILITY` | 15 |
| `LEGITIMATE_DELIVERY` | 24 |
| `LEGITIMATE_PERSONAL` | 29 |
| `LEGITIMATE_PORTAL` | 30 |
| `QR_CODE_FRAUD` | 71 |
| `INVESTMENT_CRYPTO_FRAUD` | 24 |
| `REFUND_SCAM` | 16 |
| `FAMILY_EMERGENCY_SCAM` | 24 |
| `LEGITIMATE_SECURITY` | 1 |

---

## 5. Leakage Prevention Verification
- Exact matches between Train and Test: **0**
- Exact matches between Train and Val: **0**
- Exact matches between Val and Test: **0**
- Domain overlap between Train and Test: **0** (Cluster-aware split)
- Hash verification algorithm: `SHA-256` content hashing
