# Security Engineering Policies & Architecture

> **Engineering Mandate:** Security is an immutable architectural constraint, not an afterthought. Every line of code, external dependency, and network interaction across ScamShield must adhere to defensive engineering practices.

---

## 1. Core Security Principles

1. **Least Privilege & Surface Minimization:** Components operate with the absolute minimum set of capabilities and permissions required to execute their specific function.
2. **Defense in Depth:** No single security mechanism (e.g., DNS filtering, regex check, or client-side heuristic) is trusted as the sole line of defense.
3. **Zero Trust between Subsystems:** Content scripts running on untrusted web pages are treated as potentially hostile by the background service worker. Client-side telemetry is validated server-side.
4. **Fail-Closed vs. Fail-Safe Strategy:**
   - For confirmed high-risk threats: Navigation fails closed (blocked by default).
   - For backend network failures / timeouts: The extension fails open with a warning badge, avoiding total disruption of normal browsing while alerting the user to degraded protection.
5. **Privacy by Design:** URLs and browsing paths are canonicalized, stripped of PII/tokens, and queried using k-Anonymity prefix hashing. Full raw browsing histories are never transmitted or stored.

---

## 2. Secrets Management & Environment Isolation

### 2.1 Git Repository Hygiene
- **Strict Prohibition of Secrets in Git:** API keys, database credentials, JWT secrets, WhatsApp Cloud API access tokens, and cloud private keys must never be committed to Git.
- **Automated Pre-Commit Hooks:** Local pre-commit hooks verify that `.env`, `.pem`, `.key`, and credential patterns are rejected prior to staging.
- **Environment Variable Segregation:**
  - `extension/.env.example` — Only non-sensitive public endpoints (e.g., `SCAMSHIELD_API_BASE_URL`).
  - `backend/.env.example` — Server-side environment variables template.
  - `whatsapp-bot/.env.example` — Bot credentials template.

### 2.2 Extension Secrets Policy
Under Chrome Manifest V3, **any secret embedded in client-side extension bundles is completely compromised**. The extension bundle can be unpacked and inspected by any user.
- **Zero API Secrets in Extension:** The extension communicates with ScamShield APIs using public client rate-limited endpoints or anonymous ephemeral session tokens. No master backend API keys are ever shipped within the extension bundle.

---

## 3. Input Validation & Content Security Policy (CSP)

### 3.1 Strict Input Sanitization
- All inputs received by the background service worker, WhatsApp webhook, or backend REST APIs must be validated against strict schemas (using Zod in TypeScript and Pydantic in Python).
- **URL Canonicalization:** Destination URLs must be parsed through strict WHATWG URL standards:
  - Reject unsupported schemes (`javascript:`, `data:`, `vbscript:`, `blob:`).
  - Normalize Punycode / Internationalized Domain Names (IDNs) to expose Cyrillic/Greek homoglyph attacks.
  - Strip sensitive query parameters (e.g., `token`, `auth`, `session_id`, `password`, `key`).

### 3.2 Extension Content Security Policy (CSP)
Manifest V3 enforces a strict, tamper-proof CSP:
```json
{
  "content_security_policy": {
    "extension_pages": "script-src 'self'; object-src 'self'; frame-ancestors 'none';"
  }
}
```
- Forbids `eval()`, `new Function()`, and remote script injection.
- UI views (popup, interstitial) render only locally compiled React bundles.

---

## 4. Secure Development Lifecycle & Dependency Auditing

1. **Dependency Vetting:** Before any package is added to `package.json`:
   - Inspect package size, release history, and maintainer reputation.
   - Run `npm audit` to verify zero high or critical CVEs.
   - Avoid bloated mono-libraries when lightweight standard Web APIs suffice.
2. **Continuous Vulnerability Scanning:** Automated scanning in CI/CD pipelines to catch vulnerable transitive dependencies.
3. **Reproducible Builds:** Lockfiles (`package-lock.json`) are committed and strictly enforced via `npm ci`.
