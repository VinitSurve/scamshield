# ScamShield — Multi-Provider AI Engine Architecture

> **Component:** AI Engine (`extension/src/ai/`)  
> **Providers Supported:** Google Gemini (`gemini-1.5-flash`, `gemini-1.5-pro`, `gemini-2.0-flash`) & Groq Fast Inference (`llama-3.3-70b-versatile`, `llama-3.1-8b-instant`, `mixtral-8x7b-32768`)  
> **Security Baseline:** Zero secrets in source, client-side storage isolation in `chrome.storage.local`, strict PII redaction, background worker execution boundary.

---

## 1. Executive Summary & Design Goals

The ScamShield Multi-Provider AI Engine equips the browser extension with structured semantic reasoning for SMS, WhatsApp forwards, emails, and suspicious URLs without sacrificing user privacy, security, or reliability:

1. **Multi-Key Resilience**: Configure multiple API keys per provider (e.g. 4 Gemini keys, 3 Groq keys).
2. **Health-Aware Round Robin**: Distributes request load across healthy, active keys.
3. **Automated Cooldowns (HTTP 429)**: Keys encountering rate limits or quota exhaustion automatically enter a temporary cooldown (`cooling_down`), allowing the engine to immediately attempt the next key.
4. **Seamless Provider Fallback**: If an entire provider's key pool is exhausted or unavailable, requests automatically fall back to the secondary provider (e.g., Gemini ➔ Groq).
5. **Strict Security & Privacy**: API keys are restricted to the extension's background service worker and options page, masked on display (`AIza••••••••1234`), never logged, and all prompt text is scrubbed of PII (phone numbers, OTPs, credit cards, UPI IDs, auth tokens) before calling provider APIs.
6. **Deterministic Primacy**: The deterministic threat engine (Tranco anchors, k-anonymity prefix cache, redirect hop limits) remains the primary security authority. AI assists with message comprehension and evidence explanation, but never overrides verified security blocks.

---

## 2. Architectural Blueprint

```
┌────────────────────────────────────────────────────────┐
│ UI Surfaces (Popup / Options Settings / Test Lab)      │
│ - Options: Multi-Key Manager & Provider Health Cards   │
│ - Popup: AI Scam Analyzer & Threat Explanation Modal   │
└───────────────────────────┬────────────────────────────┘
                            │ SafeMessaging (Typed Runtime Bus)
                            ▼
┌────────────────────────────────────────────────────────┐
│ Background Service Worker Execution Boundary           │
│                                                        │
│  ┌──────────────────────────────────────────────────┐  │
│  │ AIService (Master Orchestrator)                  │  │
│  │ - PiiScrubber (Strips phone, OTP, cards, UPI)    │  │
│  │ - Structured Schema Normalizer                   │  │
│  └────────────────────────┬─────────────────────────┘  │
│                           ▼                            │
│  ┌──────────────────────────────────────────────────┐  │
│  │ ProviderRouter (Priority & Fallback Routing)     │  │
│  │ Priority Order: Configurable (Gemini ➔ Groq)     │  │
│  └────────┬─────────────────────────────────┬───────┘  │
│           ▼                                 ▼          │
│  ┌─────────────────────────┐   ┌────────────────────┐  │
│  │ KeyManager              │   │ BaseAIProvider     │  │
│  │ - Multi-Key Pools       │   │ - GeminiProvider   │  │
│  │ - Round-Robin Selector  │   │ - GroqProvider     │  │
│  │ - 429 Cooldown Recovery │   │ - JSON Mode Parser │  │
│  │ - Masked Storage        │   │ - Error Classifier │  │
│  └─────────────────────────┘   └────────────────────┘  │
└────────────────────────────────────────────────────────┘
```

---

## 3. Multi-Key Management & Rotation Strategy

### Key Health States
- **`healthy`**: Active key ready to serve traffic.
- **`cooling_down`**: Key received HTTP 429 or quota limit. Assigned a cooldown timer (`cooldownUntil`). The engine skips this key until the timer expires, whereupon it is restored to `healthy`.
- **`invalid`**: Key received HTTP 401 (Authentication Failure). Bypassed permanently until the user resets or updates it.
- **`disabled`**: Manually toggled off by user.

### Round-Robin Selection
When a request is initiated:
1. `KeyManager.getNextAvailableKey(provider)` filters the provider's pool for enabled, non-invalid keys whose cooldowns have expired.
2. Selects the next key via an incrementing pointer index to balance request volume.
3. If an error occurs on that key:
   - **HTTP 429**: Cooldown is calculated (from `Retry-After` header or exponential backoff `30s * (1 + count)` up to 300s). The engine immediately rotates to the next available key for the same provider.
   - **HTTP 401**: Key marked `invalid`. Rotates to next key.
   - **HTTP 400**: Malformed request structure. Fails fast without retrying across all keys.
   - **HTTP 5xx / Timeout**: Bounded retry, then falls back to secondary provider.

---

## 4. Privacy & PII Scrubbing (`PiiScrubber`)

Before any text is sent to third-party LLM endpoints, `PiiScrubber` redacts:
- **Phone Numbers**: Matches Indian (`+91 9876543210`) and international numbers ➔ `[PHONE_NUMBER_REDACTED]`
- **OTPs & Verification Codes**: Matches 4-8 digit codes following OTP/PIN triggers ➔ `[OTP_REDACTED]`
- **Credit / Debit Cards**: Matches 16-digit card patterns ➔ `[CARD_NUMBER_REDACTED]`
- **Bank Accounts**: Matches 11-18 digit standalone numbers ➔ `[ACCOUNT_REDACTED]`
- **UPI Handles**: Matches `@okaxis`, `@okhdfcbank`, `@paytm`, `@upi`, etc. ➔ `[UPI_HANDLE_REDACTED]`
- **Sensitive URL Parameters**: Redacts `token`, `auth`, `session`, `apikey`, `secret` from URL queries.

---

## 5. Structured Output Contracts

### Scam Message Analysis Schema
```typescript
export interface StructuredScamAnalysis {
  success: boolean;
  classification: 'SAFE' | 'SUSPICIOUS' | 'SCAM' | 'MALICIOUS' | 'UNKNOWN';
  riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  confidenceScore: number; // 0.00 to 1.00
  scamCategory: string; // e.g. BANKING_KYC_PHISHING, UPI_FRAUD, ELECTRICITY_BILL_SCAM
  summary: string;
  socialEngineeringTactics: string[]; // e.g. ['Urgency', 'Authority', 'Fear']
  indicators: Array<{
    type: string;
    description: string;
    severity: 'LOW' | 'MEDIUM' | 'HIGH';
  }>;
  extractedEntities: {
    brandImpersonated?: string;
    suspiciousUrls?: string[];
    paymentRequests?: string[];
    requestedActions?: string[];
  };
  recommendedActions: string[];
  explanation: string;
  providerUsed?: AIProviderId;
  modelUsed?: string;
  latencyMs?: number;
  fallbackOccurred?: boolean;
  error?: string;
}
```

---

## 6. Verification & Automated Test Coverage

Tested across 13 suites (68 tests total):
- `tests/key-manager.test.ts`: Round-robin rotation, multi-key isolation, 429 cooldowns, masking, health stats.
- `tests/provider-router.test.ts`: Fallback routing (Gemini ➔ Groq), key rotation on 429, exhausted provider handling.
- `tests/ai-service.test.ts`: PII scrubber regexes, structured message parsing, URL evidence explanation, key validation ping.
- `tests/test-lab.test.ts`: 14 automated test cases including 4 AI engine diagnostics.
