# ScamShield Engineering Documentation

Welcome to the central technical documentation repository for **ScamShield** — an end-to-end, community-powered cyber fraud and scam prevention platform.

---

## 📑 Documentation Index

| Document | Purpose & Key Topics | Primary Audience |
| :--- | :--- | :--- |
| [**PRODUCT_OVERVIEW.md**](PRODUCT_OVERVIEW.md) | Vision, user personas, high-level features, Indian threat landscape, non-goals. | All Contributors, Product |
| [**ARCHITECTURE.md**](ARCHITECTURE.md) | System-level architecture, end-to-end component topology, data flows, integration points. | System Architects, Leads |
| [**BROWSER_EXTENSION_ARCHITECTURE.md**](BROWSER_EXTENSION_ARCHITECTURE.md) | Chrome Manifest V3 service worker lifecycle, DNR rules, navigation hooks, popup, content scripts. | Extension Engineers (Vinit) |
| [**SECURITY.md**](SECURITY.md) | Security engineering policies, secrets management, input sanitization, least-privilege boundaries. | All Engineers, DevSecOps |
| [**THREAT_MODEL.md**](THREAT_MODEL.md) | STRIDE threat model, threat actor taxonomy, attack surface enumeration, TOCTOU mitigations. | Security Engineers |
| [**URL_INVESTIGATION_SECURITY.md**](URL_INVESTIGATION_SECURITY.md) | Sandboxed automated URL analysis, SSRF prevention, DNS rebinding defenses, egress lockdown. | Backend / Sandbox Engineers |
| [**API_CONTRACTS.md**](API_CONTRACTS.md) | Versioned REST/JSON schemas connecting Extension, WhatsApp Bot, and Threat Backend. | Vinit & Shubham |
| [**DATA_MODEL.md**](DATA_MODEL.md) | Relational & cache schemas for indicators, reputations, verdicts, community reports, audits. | Backend Engineers |
| [**MULTILINGUAL_STRATEGY.md**](MULTILINGUAL_STRATEGY.md) | Indian linguistic pipeline: Hindi, Marathi, Hinglish, transliteration, phonetic normalization. | NLP / AI Engineers |
| [**COMMUNITY_INTELLIGENCE.md**](COMMUNITY_INTELLIGENCE.md) | Reputation scoring algorithm, decay mechanics, Sybil & brigade defense, dispute resolution. | Backend / Trust & Safety |
| [**IMPLEMENTATION_ROADMAP.md**](IMPLEMENTATION_ROADMAP.md) | 11-phase milestone schedule, P0/P1/P2/P3 priorities, dependencies, acceptance gates. | Project Management |
| [**TESTING.md**](TESTING.md) | Unit, integration, security, and offline browser test matrices; mock threat corpora. | QA & All Developers |
| [**PRIVACY.md**](PRIVACY.md) | Zero-telemetry policy, k-Anonymity prefix hashing, PII handling, user rights. | Compliance & Users |
| [**CONTRIBUTING.md**](CONTRIBUTING.md) | Strict Git feature branch protocols, PR templates, code review checklists, merge authority. | All Contributors |

---

## 🏛️ Architecture Decision Records (ADRs)

Key structural decisions are recorded in the [`docs/DECISIONS/`](DECISIONS/) directory:

- [**ADR-001: Chrome Manifest V3 Extension Architecture**](DECISIONS/ADR-001-browser-extension-architecture.md) — Service worker lifecycle, declarativeNetRequest vs. webNavigation navigation gating.
- [**ADR-002: Threat Intelligence API & Privacy-Preserving Lookups**](DECISIONS/ADR-002-threat-intelligence-api.md) — 32-bit k-Anonymity prefix hashing vs. full URL transmission.
- [**ADR-003: Isolated URL Investigation Execution Environment**](DECISIONS/ADR-003-url-investigation-execution.md) — Ephemeral disposable worker containers with hardened DNS pinning vs. developer machines.
- [**ADR-004: Multi-Signal Community Reputation Scoring Engine**](DECISIONS/ADR-004-reputation-model.md) — Exponential decay, reporter trust weights, and Tranco anchor protection against brigade blocking.
- [**ADR-005: Hybrid Multilingual Scam Analysis Architecture**](DECISIONS/ADR-005-multilingual-analysis.md) — Regex/heuristic intent triggers combined with transliterated phonetic normalization before LLM inference.
- [**ADR-006: Minimalist Browser Permission Model**](DECISIONS/ADR-006-browser-permission-strategy.md) — Elimination of `<all_urls>` content script injection in favor of activeTab and scoped domain declarations.

---

## 🔄 Updating Documentation

1. Documentation is living code: updates require the same feature branch and PR workflow defined in [CONTRIBUTING.md](CONTRIBUTING.md).
2. Never document aspirational features as existing implementations. Clearly separate **Implemented**, **In-Progress**, and **Planned** states.
3. Every new external dependency or architectural change must be accompanied by an update to the respective document and an ADR.
