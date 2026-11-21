# Product Overview — ScamShield

> **Think Before You Click.**
> A community-powered, privacy-first cybersecurity ecosystem built to neutralize online fraud, social engineering, and financial deception across browsers and conversational channels.

---

## 1. Executive Summary

Digital scams in India and emerging economies have evolved beyond crude spam emails into sophisticated, multi-stage social engineering campaigns. Fraudsters leverage localized urgency, impersonate government agencies (e.g., Income Tax, e-Challan, Electricity Boards), mimic premier banking portals (SBI, HDFC, ICICI), and deploy deceptive redirect chains via SMS, WhatsApp, and social media.

**ScamShield** bridges the gap between passive endpoint antivirus tools and complex enterprise threat platforms. By coupling an intelligent Chromium browser extension with a WhatsApp verification bot backed by a shared intelligence engine, ScamShield delivers real-time, explainable, and privacy-preserving protection right at the point of attack.

---

## 2. Problem Statement

1. **Deceptive Redirect Funnels:** Users click legitimate-appearing short links (e.g., bit.ly, tinyurl, or compromised news portals) that bounce through affiliate trackers and advertising hops before landing on high-risk credential-harvesting pages.
2. **Linguistic Complexity & Romanized Dialects:** Attackers bypass traditional English-only keyword filters by crafting lures in Romanized Hindi (Hinglish), Marathi, or mixed vernacular scripts (e.g., *"Aapka electricity connection aaj raat 9:30 baje disconnect ho jayega. Bill update karne ke liye click karein"*).
3. **Impersonation of Indian Financial Infrastructure:** Phishing attacks routinely target Unified Payments Interface (UPI) handles, fake QR codes, and faux KYC update portals.
4. **Privacy vs. Protection Dilemma:** Existing threat extensions frequently exfiltrate complete browsing histories and full URLs (including sensitive query parameters) to centralized servers, introducing privacy violations.
5. **Slow Threat Dissemination:** New scam campaigns can target thousands of victims within hours before traditional threat feeds (like Google Safe Browsing) register and index the malicious domains.

---

## 3. Product Vision & Target Audience

### Vision
To create a decentralized, community-validated, real-time threat intelligence network that proactively halts scam interactions across all primary digital communication and browsing surfaces.

### Primary User Personas
- **The Everyday Consumer (Primary):** Browses social media, reads email, and conducts online banking. Needs frictionless, zero-latency safety warnings without cryptographic jargon.
- **Vulnerable Family Members (Seniors & First-Time Digital Users):** High susceptibility to panic-inducing SMS/WhatsApp messages claiming bank accounts or SIM cards are blocked.
- **Community Threat Reporter:** Cybersecurity enthusiasts and active digital citizens who discover scam domains/UPI handles and report them to protect the broader collective.

---

## 4. Key Functional Capabilities

### A. Browser Extension (Chromium Manifest V3)
- **Zero-Latency Local Gating:** High-confidence offline Bloom filter / prefix cache for instant blocking of confirmed malicious domains without network latency.
- **Privacy-Preserving Remote Reputation:** 32-bit k-Anonymity prefix lookups ensuring the backend never knows the full destination URL being visited.
- **Dynamic Redirect Tracing:** Tracks navigational hops across origin boundaries to catch deceptive landing destinations.
- **Educational Warning Interstitials:** Explains the specific evidence behind a block (e.g., *"This domain was created 4 hours ago and impersonates SBI NetBanking"*).
- **In-Browser Heuristic Analysis:** Detects deceptive login interfaces, spoofed top-level domains (TLDs), and homoglyph attacks without scraping user keystrokes.
- **Gmail Web Threat Gating:** Evaluates sender envelope alignment, reply-to anomalies, and high-risk embedded links in webmail interfaces.
- **One-Click Community Reporting:** Allows users to submit suspicious URLs directly from the browser popup with automated metadata gathering.

### B. WhatsApp Scam-Analysis Bot (Shubham Workstream)
- **Conversational Verification:** Users forward suspicious text messages, payment screenshots, or links directly to the WhatsApp bot.
- **Vernacular Analysis:** Native understanding of English, Hindi, Marathi, and Hinglish urgency cues, financial traps, and coercive patterns.
- **Entity Extraction:** Parses UPI IDs, bank account patterns, phone numbers, and shortened links.
- **Consent-Driven Investigation:** Invites the user to consent before triggering an isolated, sandboxed URL investigation.
- **Actionable Remediation:** Provides immediate steps if the user has already clicked or shared credentials (e.g., dial 1930 for National Cyber Crime Reporting, freeze bank accounts).

### C. Shared Threat Intelligence Platform
- **Unified Indicator Store:** Cross-platform sharing of malicious URLs, IPs, UPI handles, and scam message hashes.
- **Sandboxed Investigation Dispatcher:** Fully isolated, disposable execution environments to render and photograph malicious URLs safely without risking infrastructure.
- **Community Reputation Engine:** Multi-signal confidence scoring with time-based decay, reporter trust weightings, and dispute workflows.

---

## 5. Non-Goals & Architectural Boundaries

To maintain velocity, security, and hackathon feasibility, the following are strictly non-goals:
- **No Full Antivirus / Malware Payload Disinfection:** ScamShield does not analyze system binary executables (.exe, .dmg) or claim to replace native OS antivirus engines.
- **No Keystroke or Form Data Harvesting:** ScamShield will never capture or inspect user passwords, credit card numbers, or form inputs.
- **No Universal Email Client Desktop Hook:** Protection is strictly focused on supported webmail (initially Gmail Web in Chrome), not Outlook Desktop, Apple Mail, or Thunderbird.
- **No Bypass of Enterprise Firewalls / Zero Trust Proxies:** ScamShield operates at the browser/application layer for consumer safety, not as an enterprise VPN/SASE proxy.
- **No Real-Time Keystroke MITM:** We do not intercept DOM input events to sniff passwords.
