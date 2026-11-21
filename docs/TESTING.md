# Comprehensive Testing Strategy & Quality Assurance

> **Standard:** In cybersecurity software, unverified assumptions produce vulnerabilities. We mandate automated unit testing, end-to-end browser simulation, offline behavior validation, and adversarial security testing.

---

## 1. Test Matrix & Scenarios

### 1.1 URL Navigation Test Suite
| Case ID | Scenario | Input Target | Expected Outcome |
| :--- | :--- | :--- | :--- |
| `URL-01` | Legitimate Top-Ranked Site | `https://google.com`, `https://onlinesbi.sbi` | Instant pass; zero latency; no interstitial. |
| `URL-02` | Known Malicious Phishing Domain | `http://sbi-kyc-update-portal.top` | Immediately blocked in `onBeforeNavigate`; redirected to interstitial. |
| `URL-03` | Unindexed Unknown Domain | `https://random-new-shop-123.store` | Fast k-anonymity check; passes with neutral badge; passive heuristics monitor DOM. |
| `URL-04` | Multi-Hop Deceptive Redirect | `bit.ly/3x -> affiliate.tracker -> evil-bank.com` | Traced at intermediate hop; blocked before final render. |
| `URL-05` | Infinite Redirect Loop | `domainA -> domainB -> domainA` | Terminated after 5 hops; warning displayed: `REDIRECT_LOOP_ABORTED`. |
| `URL-06` | SSRF Attempt to Localhost | `http://127.0.0.1:8080/admin` | Extension skips internal schemes; Sandbox runner drops connection immediately. |
| `URL-07` | SSRF Attempt to Cloud Metadata | `http://169.254.169.254/latest/meta-data/` | Hard drop by CIDR validator; zero bytes transmitted. |
| `URL-08` | Punycode / IDN Homoglyph Attack | `http://xn--80ak6aa92e.com` (`apple.com` in Cyrillic) | Decoded to Unicode; flagged as `PUNYCODE_HOMOGLYPH_IMPERSONATION`. |
| `URL-09` | Offline / Degraded Network | Wi-Fi disabled | Cached threats blocked; unknown domains allowed with offline indicator badge. |

### 1.2 Indian Multilingual Scam Message Test Suite
| Case ID | Language / Script | Test Message Lure | Expected Classification |
| :--- | :--- | :--- | :--- |
| `MSG-01` | English Formal Phishing | *"Your ICICI account has been suspended due to incomplete PAN card. Click here to verify."* | **SCAM (Banking Phishing)** |
| `MSG-02` | Hinglish Urgency Lure | *"Aapka electricity connection aaj raat 9:30 baje cut ho jayega. Turant call karein 9876543210."* | **SCAM (Electricity Lure)** |
| `MSG-03` | Marathi Vernacular Lure | *"तुमचे बँक खाते आज बंद होणार आहे. त्वरित KYC अपडेट करा: https://s.id/kyc-mr"* | **SCAM (Banking Phishing)** |
| `MSG-04` | Romanized Marathi | *"Tumcha light bill baki aahe. Lagach update kara nahi tar power cut honar."* | **SCAM (Electricity Lure)** |
| `MSG-05` | Legitimate Banking Notification | *"Your A/C ending in 4091 has been debited by INR 500 on 21-Nov via UPI Ref 412345. If not you, SMS BLOCK to 567676."* | **LEGITIMATE (Notification)** |
| `MSG-06` | Adversarial Zero-Width Space | *"S​B​I K​Y​C u​p​d​a​t​e n​o​w"* (contains `U+200B`) | Cleaned in Stage 1; classified as **SCAM**. |

---

## 2. Testing Frameworks & Setup

```bash
# In extension/
npm run test:unit       # Vitest for URL canonicalizer, k-anonymity client, cache
npm run test:e2e        # Playwright with loaded Chromium extension
npm run lint            # ESLint with strict TypeScript rules
npm run typecheck       # tsc --noEmit
```

### Mocking Chrome APIs in Vitest
```typescript
import { vi, describe, it, expect } from 'vitest';
import { canonicalizeUrl, hashDomainPrefix } from '../src/shared/url';

describe('URL Canonicalizer', () => {
  it('strips query parameters and fragments for privacy', () => {
    const raw = 'https://sbi-login.xyz/auth?session_id=SECRET_TOKEN#step2';
    const result = canonicalizeUrl(raw);
    expect(result.domain).toBe('sbi-login.xyz');
    expect(result.sanitizedUrl).toBe('https://sbi-login.xyz/auth');
  });

  it('generates accurate 32-bit hex hash prefix', async () => {
    const prefix = await hashDomainPrefix('sbi-login.xyz');
    expect(prefix).toHaveLength(8);
    expect(prefix).toMatch(/^[0-9a-f]{8}$/);
  });
});
```
