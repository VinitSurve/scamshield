# ScamShield

> **Think Before You Click.**
> Proactive, community-powered digital threat and scam protection ecosystem designed for modern internet users.

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Branch](https://img.shields.io/badge/branch-main-brightgreen.svg)](https://github.com/VinitSurve/scamshield)
[![Manifest](https://img.shields.io/badge/manifest-v3-orange.svg)](docs/BROWSER_EXTENSION_ARCHITECTURE.md)

---

## 🛡️ Project Overview

ScamShield protects ordinary internet users against digital fraud, phishing campaigns, deceptive redirect loops, fraudulent payment gateways, fake KYC demands, and malicious impersonation. Built with an Indian and multilingual-first threat intelligence posture, ScamShield shields users across their primary digital touchpoints: **Browser Extension** and **WhatsApp Assistance**.

### Multi-Platform Ecosystem

| Component | Lead / Owner | Primary Responsibilities | Directory |
| :--- | :--- | :--- | :--- |
| **Browser Extension** | **Vinit Surve** | Manifest V3 Chromium extension, navigation interception, redirect tracing, Gmail scam analysis, warning interstitial, local reputation cache | `extension/` |
| **WhatsApp Threat Bot** | **Shubham** | WhatsApp Cloud API webhook, forwarded scam message parser, Hinglish/Marathi text classifier, UPI/phone threat verification, consent-based deep URL investigation | `whatsapp-bot/` |
| **Intelligence Backend & APIs** | Shared / Unified | Shared threat evaluation engine, k-Anonymity reputation lookups, community reporting scoring, sandboxed URL investigation dispatcher | `backend/` |
| **Dashboard** | Full-Stack | Threat monitoring, community dispute resolution, system analytics, research metrics | `dashboard/` |

---

## 📚 Engineering Documentation

Comprehensive architecture, security threat models, shared API contracts, and implementation blueprints are maintained inside the [`docs/`](docs/README.md) directory:

- 📖 [**Product Overview & Vision**](docs/PRODUCT_OVERVIEW.md)
- 🏗️ [**System Architecture & Data Flow**](docs/ARCHITECTURE.md)
- 🧩 [**Browser Extension Architecture (Manifest V3)**](docs/BROWSER_EXTENSION_ARCHITECTURE.md)
- 🔒 [**Security Specifications & Practices**](docs/SECURITY.md)
- 🎯 [**Threat Model & Attack Surface Analysis**](docs/THREAT_MODEL.md)
- 🔬 [**Isolated URL Investigation & Sandbox Defenses**](docs/URL_INVESTIGATION_SECURITY.md)
- 🔌 [**Shared API Contracts (Browser & WhatsApp)**](docs/API_CONTRACTS.md)
- 🗄️ [**Unified Data Model & Schemas**](docs/DATA_MODEL.md)
- 🌐 [**Multilingual Scam Strategy (Hinglish/Marathi)**](docs/MULTILINGUAL_STRATEGY.md)
- 👥 [**Community Threat Intelligence & Reputation Decay**](docs/COMMUNITY_INTELLIGENCE.md)
- 🛣️ [**Phased Implementation Roadmap**](docs/IMPLEMENTATION_ROADMAP.md)
- 🧪 [**Testing Strategy & Quality Gates**](docs/TESTING.md)
- 🔐 [**Privacy Policy & Telemetry Boundary**](docs/PRIVACY.md)
- 🤝 [**Mandatory Git Collaboration & PR Workflow**](docs/CONTRIBUTING.md)
- 📋 [**Architecture Decision Records (ADRs)**](docs/DECISIONS/)

---

## ⚡ Quick Start for Developers

### Git Collaboration Rule
> [!IMPORTANT]
> **Direct pushes to `main` are strictly forbidden.** All work must be conducted on isolated feature branches (`vinit-feature-name` or `shubham-feature-name`) and submitted via Pull Requests for review. See [CONTRIBUTING.md](docs/CONTRIBUTING.md).

```bash
# Clone the repository
git clone https://github.com/VinitSurve/scamshield.git
cd scamshield

# Always branch from clean main
git checkout main
git pull origin main
git checkout -b vinit-feature-name
```

---

## ⚖️ License & Disclaimers

ScamShield is developed as an open-source cybersecurity project. Real-time threat classification is advisory and probabilistic. Passive and active URL investigations adhere to strict network safety boundaries without executing active exploitation payloads.
