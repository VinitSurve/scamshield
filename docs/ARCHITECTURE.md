# System Architecture & Topology — ScamShield

This document details the high-level architecture of the ScamShield ecosystem, defining how components interact, communication protocols, trust boundaries, and shared services across the Browser Extension and WhatsApp Bot workstreams.

---

## 1. High-Level Architectural Diagram

```mermaid
flowchart TD
    subgraph Client_Surface ["Client Touchpoints"]
        ext["Browser Extension\n(Chromium Manifest V3)\n[Vinit]"]
        wa["WhatsApp User\n(Mobile / Web)\n[End User]"]
        dash["ScamShield Web Dashboard\n(Next.js 16 + Tailwind)\n[Full-Stack]"]
    end

    subgraph Ingestion_Edge ["Ingestion & Edge Services"]
        waboot["WhatsApp Bot Gateway\n(Webhook / Baileys)\n[Shubham]"]
        api["ScamShield Intelligence API\n(FastAPI / Node Express)\n[Shared Gateway]"]
    end

    subgraph Core_Services ["ScamShield Core Intelligence Engine"]
        repEngine["Reputation & Scoring Engine\n(Decay, Trust Weights, Tranco)"]
        multiNLP["Multilingual NLP Pipeline\n(Hinglish, Marathi, Normalizer)"]
        redirectTracker["Redirect & Hop Analyzer"]
        bloomBuilder["Bloom Filter / Local Cache Generator"]
    end

    subgraph Sandboxed_Execution ["Isolated Investigation Sandbox"]
        jobQueue["Investigation Queue\n(Redis / BullMQ)"]
        disposableWorker["Disposable Worker Container\n(Hardened Chromium, Egress Filter)\n[Ephemeral]"]
    end

    subgraph Storage_Layer ["Persistence & Threat Cache"]
        redisCache["Redis (L1 Threat Cache &\nk-Anonymity Prefixes)"]
        postgresDB["PostgreSQL\n(Threat DB, Reports, Audits, Evidence)"]
        objectStore["Encrypted Object Storage\n(Sanitized Screenshots & DOM Dumps)"]
    end

    ext -->|"k-Anonymity SHA-256 (32-bit prefix)\nLocal Cache Sync"| api
    ext -->|"Community Report"| api
    wa -->|"Forwarded Text, Links, UPI"| waboot
    waboot -->|"Analyze Message / Trigger Investigation"| api
    dash -->|"Admin Review & Dispute Mgmt"| api

    api --> repEngine
    api --> multiNLP
    api --> redirectTracker
    api --> jobQueue

    jobQueue --> disposableWorker
    disposableWorker -->|"Sanitized Evidence\n& Final Destination"| objectStore
    disposableWorker -->|"Investigation Result"| api

    repEngine --> postgresDB
    repEngine --> redisCache
    bloomBuilder --> redisCache
```

---

## 2. Component Ownership & Directory Boundaries

To guarantee seamless parallel development between Vinit Surve and Shubham, the repository is partitioned into strictly isolated workspaces with explicit interface contracts:

```
scamshield/
├── dashboard/               # Next.js 16 + Tailwind dashboard (Admin & Community review)
├── extension/               # Chrome MV3 Extension (Vinit - Primary Focus)
│   ├── src/
│   │   ├── background/      # Service Worker (Navigation, DNR, Cache, Messaging)
│   │   ├── content/         # Scoped Content Scripts (DOM heuristic checks, Gmail web)
│   │   ├── popup/           # React popup UI (Status, Report URL, Preferences)
│   │   ├── interstitial/    # Safe Warning Screen for blocked navigation
│   │   ├── shared/          # Typed schemas, cryptographic hashing, utils
│   │   └── manifest.json    # Manifest V3 configuration
│   ├── package.json
│   └── tsconfig.json
├── whatsapp-bot/            # WhatsApp Verification Bot (Shubham - Primary Focus)
│   ├── src/
│   │   ├── webhook/         # WhatsApp Cloud API / Webhook handlers
│   │   ├── classification/  # Text extraction, NLP intent parsing
│   │   ├── handlers/        # Conversational state machine & user guidance
│   │   └── client/          # API client calling ScamShield Shared Intelligence
│   ├── package.json
│   └── tsconfig.json
├── backend/                 # Shared Intelligence Engine & API Gateway
│   ├── src/
│   │   ├── api/v1/          # Versioned REST endpoints (OpenAPI / Swagger)
│   │   ├── engine/          # Reputation scoring, decay, Tranco check
│   │   ├── multilingual/    # Indian languages transliteration & regex rules
│   │   └── sandbox/         # Job queue dispatcher for isolated runner
│   └── tests/
├── worker/                  # Ephemeral URL Investigation Worker (Docker / Podman)
│   ├── Dockerfile           # Minimal distroless container, no persistent secrets
│   └── runner/              # Headless browser runner with DNS-pinning & egress firewall
└── docs/                    # Complete architectural, security, and integration docs
```

---

## 3. End-to-End Data Flow

### Flow 1: Real-Time Browser Navigation Gating
1. **User clicks or navigates to a URL** in Google Chrome.
2. **Local Tier 1 Check (0ms):**
   - The Extension Service Worker queries its local in-memory Bloom filter / IndexedDB cache of known high-confidence malicious domains.
   - If hit: Navigation is immediately halted and redirected to `chrome-extension://<id>/interstitial.html?blocked_url=...` with cached threat evidence.
3. **Remote Tier 2 Check (k-Anonymity Prefix Lookup):**
   - If not in local cache and domain is not in the Tranco Top 100K list, the extension computes:
     `Hash = SHA-256(canonical_domain)`
     `Prefix = Hash.substring(0, 8)` (32 bits)
   - Extension sends `GET /api/v1/reputation/prefix/{Prefix}`.
   - The backend returns an array of known threat hashes matching that 32-bit prefix (typically 2–10 entries).
   - The extension checks locally if its full `Hash` is in the returned list.
   - **Crucial Privacy Guarantee:** The backend *never receives the domain name or URL* being visited.
4. **Verdict Render:**
   - If match found with high risk: Navigate to local warning interstitial.
   - If unknown or clean: User proceeds transparently without perceptible latency.

### Flow 2: Deceptive Redirect Chain Interception
```mermaid
sequenceDiagram
    autonumber
    actor User
    participant Browser as Chrome Browser
    participant SW as Service Worker (Extension)
    participant Origin as Initial Site (bit.ly/xyz)
    participant Redir as Intermediate Hop (tracker.ad)
    participant Final as Malicious Destination (phish-sbi.top)

    User->>Browser: Click short link bit.ly/xyz
    Browser->>Origin: HTTP GET
    SW->>SW: Record Hop 1: bit.ly/xyz (Safe)
    Origin-->>Browser: 301 Redirect -> tracker.ad/click?id=123
    Browser->>Redir: HTTP GET
    SW->>SW: Record Hop 2: tracker.ad (Intermediate Tracking)
    Redir-->>Browser: 302 Redirect -> phish-sbi.top/login
    Browser->>SW: webNavigation.onBeforeNavigate (phish-sbi.top)
    SW->>SW: Evaluate domain change & Destination Reputation
    SW->>SW: Local Match: phish-sbi.top is VERIFIED_PHISHING
    SW->>Browser: chrome.tabs.update(tabId, interstitial.html)
    Browser-->>User: Display Educational Security Warning Interstitial!
```

### Flow 3: WhatsApp Scam Verification & Sandbox Investigation
```mermaid
sequenceDiagram
    autonumber
    actor Victim as WhatsApp User
    participant Bot as WhatsApp Bot (Shubham)
    participant API as Intelligence API
    participant Worker as Sandboxed Runner
    
    Victim->>Bot: Forwards: "Bijli bill update karo turant: s.id/bijli"
    Bot->>API: POST /api/v1/analyze/message
    API->>API: Multilingual NLP: Hindi/Hinglish urgency + electricity scam pattern
    API-->>Bot: High Risk (Electricity Scam), Extracted URL: s.id/bijli
    Bot-->>Victim: Warning: This message resembles a common scam. Deep investigate link?
    Victim->>Bot: Replies "YES"
    Bot->>API: POST /api/v1/investigations (s.id/bijli)
    API->>Worker: Dispatch isolated job
    Worker->>Worker: Hardened DNS check (Reject 127.0.0.1, 10.0.0.0/8, 169.254.169.254)
    Worker->>Worker: Headless render, follow redirects, capture sanitized screenshot
    Worker-->>API: Result: Landed on "fake-state-electricity.top", harvest form detected
    API-->>Bot: Investigation completed: Confirmed Phishing
    Bot-->>Victim: 🚨 DANGER: Link leads to fake billing site. Do not enter card/OTP!
```

---

## 4. Trust Boundaries & Network Segregation

1. **Client Untrusted Boundary:** Browser extension content scripts run in the context of arbitrary, potentially hostile web pages. Content scripts must never hold API secret keys, must never have access to sensitive extension storage, and must communicate with the Background Service Worker exclusively via strictly validated message passing.
2. **Investigation Sandbox Boundary:** The URL investigation worker processes untrusted, malicious links. It must be network-isolated from any private database, VPC internal interfaces, cloud metadata endpoints (`169.254.169.254`), and must execute with non-root credentials inside an ephemeral container that is destroyed immediately post-execution.
3. **Backend Service Boundary:** All public endpoints enforce token bucket rate limiting, strict JSON schema validation, and TLS 1.3 encryption.
