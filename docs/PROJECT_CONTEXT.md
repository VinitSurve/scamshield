# SCAMSHIELD — COMPLETE PROJECT CONTEXT, PRODUCT VISION & ENGINEERING MASTER BRIEF

## 1. PROJECT IDENTITY

**Project Name:** ScamShield  
**Tagline:** Think Before You Click.  
**Event:** MindSprint 2026 — The Doomsday Hackathon  
**Theme:** Cybersecurity  
**Team:** ScamShield  
**Organizers:** Hackathon Club + DSC  
**Hackathon Start:** November 21, 2026  
**Reporting Time:** 9:00 AM  
**Project Repository:** https://github.com/VinitSurve/scamshield

ScamShield is a cybersecurity-focused scam detection and protection platform designed to help ordinary users identify scams, phishing attempts, fraudulent messages, malicious websites, deceptive links, financial fraud attempts, and digital impersonation.

The project is being developed for a hackathon, but the product vision is to build something that is genuinely useful, technically defensible, security-conscious, practical, and potentially scalable beyond the hackathon.

We are not building a generic chatbot that says whether something "looks suspicious."

We are building a **multi-layer scam intelligence and protection ecosystem**.

---

# 2. THE PROBLEM WE ARE SOLVING

People increasingly receive fraudulent communications through:

- WhatsApp messages
- SMS
- Emails
- Instagram and social media DMs
- Fake customer support messages
- Fake delivery notifications
- Fake bank messages
- Fake KYC updates
- UPI payment requests
- Fake government notices
- Fake electricity bills
- Fake traffic challans
- Job and internship scams
- Investment scams
- Loan scams
- Lottery and prize scams
- QR code payment scams
- Fake websites
- Phishing links
- URL shorteners
- Malicious redirects
- Brand impersonation
- Fake apps and downloads

The typical user cannot reliably determine whether a message, URL, website, payment request, or sender is legitimate.

Scammers increasingly use:

- Urgency and psychological manipulation
- Financial fear
- Account suspension threats
- Fake rewards
- Fake government identities
- Brand impersonation
- Homoglyph domains
- Typosquatting
- URL shorteners
- Redirect chains
- Fake KYC portals
- OTP harvesting
- Credential harvesting
- Social engineering
- AI-generated messages
- Deepfake voice/video
- Fake customer-support numbers

The biggest problem is not simply that users receive suspicious messages.

The problem is:

**Users are often forced to make a security decision before they have the knowledge or tools to evaluate the threat.**

ScamShield aims to provide that knowledge and protection at the moment the user needs it.

---

# 3. CORE PRODUCT VISION

ScamShield should work as a user's digital security companion.

The user should be able to:

1. Receive a suspicious message.
2. Forward it to ScamShield.
3. Get an understandable analysis.
4. Understand what specifically makes it suspicious.
5. Identify dangerous links, impersonation, fraud patterns, and malicious destinations.
6. Decide what to do safely.
7. Investigate suspicious links further when necessary.
8. Protect themselves while browsing websites.
9. Report scams to help improve community intelligence.
10. Benefit from shared threat intelligence across ScamShield's ecosystem.

The product should focus on **actionable security**, not just classification.

A verdict without an explanation is not enough.

A useful result should answer:

- Is this suspicious?
- What evidence was detected?
- What could the attacker be trying to do?
- What information could be stolen?
- What should I avoid doing?
- What should I do instead?
- How confident is ScamShield?
- What sources were checked?
- What limitations exist?

---

# 4. PRODUCT ECOSYSTEM

ScamShield consists of multiple components that should eventually share a common threat-intelligence and analysis backend.

## Component A — WhatsApp Scam Detection Bot

Development owner: Shubham

The WhatsApp bot is designed to make scam detection accessible to users without requiring them to install a browser extension or learn cybersecurity.

### User workflow

1. User receives a suspicious WhatsApp message.
2. User forwards the message to ScamShield.
3. ScamShield analyzes the message.
4. The bot returns a readable verdict.
5. If the message contains suspicious URLs, ScamShield extracts and analyzes them.
6. The bot identifies suspicious language, urgency, impersonation, financial requests, and fraud patterns.
7. If deeper URL investigation is required, the bot asks for user consent.
8. If the user agrees, a deeper investigation workflow is initiated.
9. The user receives the final result and security recommendations.

### Message analysis capabilities

Potential detection categories:

- Phishing
- Financial fraud
- Fake KYC
- Fake bank communication
- Fake delivery notification
- Government impersonation
- Fake challan
- Electricity bill scam
- Fake job offer
- Investment fraud
- Loan scam
- Lottery scam
- OTP theft
- Credential harvesting
- UPI fraud
- Social engineering
- Suspicious urgency
- Threats and intimidation
- Suspicious payment requests
- Suspicious links

### Example

User forwards:

"Your SBI account will be blocked today. Complete KYC immediately by clicking this link."

ScamShield should explain:

- SBI impersonation indicators
- Account suspension urgency
- KYC manipulation
- Suspicious destination domain
- Potential credential theft
- Potential financial fraud

The response should explain the evidence rather than simply saying "Scam."

---

## Component B — Browser Extension

Development owner: Vinit

Repository:

https://github.com/VinitSurve/scamshield

The browser extension is currently the primary development focus.

### Objective

Protect users while browsing by detecting potentially dangerous websites, suspicious links, phishing pages, brand impersonation, deceptive redirects, and known malicious destinations.

The extension should provide protection before the user submits sensitive information or interacts with a malicious website whenever technically possible.

### Target Platform

- Google Chrome
- Chromium-based browsers
- Manifest V3

### Main functionality

#### 1. Website Scanning

Analyze the currently active website.

The scanner should examine:

- Domain
- URL structure
- Registrable domain
- Threat reputation
- Brand impersonation
- Domain similarity
- Suspicious keywords
- Homoglyphs
- Punycode
- HTTPS/TLS characteristics
- Redirect history
- Available threat intelligence
- Local cache
- Community reports

#### 2. Proactive Browser Protection

Detect dangerous destinations and provide appropriate warnings.

Potential protections:

- Known malicious domain blocking
- Suspicious destination warnings
- Brand impersonation warnings
- Redirect destination warnings
- High-risk website interstitials
- Safe return navigation
- User override with explicit warning

Security decisions must not rely solely on whether the browser displays HTTPS.

#### 3. Reputation Checking

Check domains against available ScamShield threat intelligence.

Possible sources:

- ScamShield backend
- Community threat reports
- External threat-intelligence providers
- Local cache
- Local heuristics

API failures must never silently convert an unknown website into a trusted website.

#### 4. URL Protection

Analyze URLs before navigating whenever technically supported.

Potential detection:

- Malicious URL reputation
- Suspicious domain
- Brand impersonation
- Typosquatting
- Homoglyphs
- Punycode
- URL shorteners
- Suspicious redirects
- Credential harvesting destinations

#### 5. Website Content Analysis

Where technically and ethically appropriate, inspect website structure for indicators such as:

- Password fields
- OTP fields
- Payment information forms
- Financial information collection
- Brand mismatch
- Form submission destinations
- Suspicious urgency language
- Fake verification prompts
- Fake KYC portals

The extension must never harvest user-entered values.

No keylogging.

No collecting passwords.

No collecting OTP values.

No reading sensitive form contents.

#### 6. Gmail Protection

Potentially detect:

- Sender display-name impersonation
- Sender email mismatches
- Suspicious links
- Dangerous attachments where supported
- Phishing indicators

Gmail integration must be scoped to the intended Gmail interface.

Avoid collecting email contents unnecessarily.

#### 7. Community Reporting

Users should be able to report suspicious websites.

Reports may include:

- Domain
- Threat category
- Report reason
- Optional evidence
- Timestamp

Reports should be queued locally if offline.

The extension must avoid exposing unnecessary user browsing data.

#### 8. Settings

Potential settings:

- Protection enabled/disabled
- Language
- API configuration
- Whitelist
- Cache management
- Community reporting
- Protection preferences

The settings must actually persist.

---

# 5. CURRENT BROWSER EXTENSION IMPLEMENTATION

A first implementation has already been developed on the feature branch.

**Branch:**

`vinit-browser-extension-mvp`

**Pull Request:**

https://github.com/VinitSurve/scamshield/pull/new/vinit-browser-extension-mvp

The current implementation reportedly includes:

- Manifest V3 architecture
- TypeScript
- React popup
- Settings page
- Warning interstitial
- Background service worker
- URL normalization
- Domain normalization
- Brand impersonation detection
- Homoglyph detection
- Local threat cache
- Reputation service
- API client
- Redirect tracker
- DeclarativeNetRequest integration
- Navigation monitor
- Gmail protection
- Community reporting
- English localization
- Hindi localization
- Marathi localization
- Unit tests
- Production build

### Existing extension architecture

```text
extension/
├── manifest.json
├── package.json
├── tsconfig.json
├── popup.html
├── options.html
├── interstitial.html
├── dist/
├── scripts/
│   └── build.js
└── src/
    ├── background/
    │   ├── service-worker.ts
    │   ├── navigation-monitor.ts
    │   ├── redirect-tracker.ts
    │   └── dnr-manager.ts
    ├── content/
    │   ├── content-script.ts
    │   └── gmail.ts
    ├── popup/
    │   ├── PopupApp.tsx
    │   └── components/
    │       ├── Header.tsx
    │       ├── StatusCard.tsx
    │       ├── QuickActions.tsx
    │       └── ReportModal.tsx
    ├── options/
    │   └── OptionsApp.tsx
    ├── interstitial/
    │   └── InterstitialApp.tsx
    ├── security/
    │   ├── url-validator.ts
    │   ├── domain-normalizer.ts
    │   └── safe-messaging.ts
    ├── services/
    │   ├── api-client.ts
    │   ├── reputation-service.ts
    │   └── report-service.ts
    ├── storage/
    │   ├── cache-service.ts
    │   └── settings-service.ts
    ├── i18n/
    │   ├── en.ts
    │   ├── hi.ts
    │   └── mr.ts
    └── utils/
        ├── crypto.ts
        └── logger.ts
```

### Reported test results

The implementation report claims:

- 9 test suites
- 39 tests passing
- TypeScript validation successful
- Production build successful

These results must be independently verified.

Unit tests are not equivalent to browser-level testing.

The extension must still be manually tested in Chrome or using genuine browser automation.

---

# 6. IMPORTANT CURRENT DEVELOPMENT PRIORITY

We are currently testing the extension manually in Chrome.

The extension popup currently shows:

- Current website/domain
- Website verification status
- Risk assessment percentage
- Evidence
- Scan Website button
- Report Scam button
- Protection status
- Settings

We want to understand and validate exactly how ScamShield classifies websites.

The extension must not make arbitrary claims such as:

"100% safe"

"AI verified safe"

"Completely secure"

"Guaranteed legitimate"

A low-risk score does not mean a website is verified safe.

---

# 7. EXPLAINABLE THREAT DETECTION ENGINE

This is one of the most important parts of the project.

ScamShield should use a multi-layer detection engine rather than relying on one AI model or one heuristic.

Every verdict must be explainable.

The system should be able to explain:

- Which signals were detected
- Which signals were not detected
- Which sources were checked
- Which sources were unavailable
- What contributed to the risk score
- Why a particular verdict was selected
- How reliable the available evidence is

## Detection Layer 1 — URL Analysis

Analyze:

- URL length
- Domain length
- Subdomain count
- Suspicious characters
- IP-address URLs
- Unicode characters
- Punycode
- Homoglyphs
- URL shorteners
- Suspicious keywords
- Encoded characters
- Misleading paths
- Query parameters
- Domain/path brand mismatches
- Registrable domain

Examples:

```text
https://sbi.co.in
```

Versus:

```text
https://sbi-secure-kyc-verification.xyz
```

The scanner must analyze the actual registrable domain, not simply search for the string "SBI."

---

## Detection Layer 2 — Brand Impersonation

Maintain a registry of official brand domains.

Potential initial brands:

- SBI
- HDFC Bank
- ICICI Bank
- Axis Bank
- Paytm
- PhonePe
- Google
- Microsoft
- Amazon
- Apple
- Government services
- Indian transport/challan portals
- Electricity providers

Detection methods:

- Official-domain matching
- Typosquatting
- Levenshtein distance
- Damerau-Levenshtein distance
- Homoglyph detection
- Unicode confusable analysis
- Brand keyword/domain mismatch
- Suspicious TLD
- Subdomain deception

Examples:

```text
hdfcbank.com
```

Legitimate official-domain match.

```text
hdfcbank.com.fake-login.xyz
```

Actual registrable domain is `fake-login.xyz`.

```text
hdfc-secure-verification.xyz
```

Possible impersonation.

A suspicious brand match should not automatically mean confirmed malware.

---

## Detection Layer 3 — Threat Intelligence

Check available reputation sources for:

- Phishing
- Malware
- Fraud
- Social engineering
- Unwanted software
- Suspicious destinations

Potential sources:

- ScamShield database
- Community intelligence
- Google Safe Browsing / Web Risk where integration is possible and permitted
- PhishTank
- URLhaus
- OpenPhish
- Other reliable threat intelligence providers

Each source should be recorded in the evidence.

The system must distinguish:

- Confirmed threat
- No known threat
- Source unavailable
- Source not checked
- Cached result

---

## Detection Layer 4 — Domain Intelligence

Where available:

- Domain registration date
- Domain age
- Registrar
- RDAP data
- DNS records
- Nameserver information
- Hosting provider
- IP reputation
- ASN reputation

A newly registered domain is a risk factor, not proof of a scam.

---

## Detection Layer 5 — HTTPS/TLS

Analyze:

- HTTPS availability
- Certificate validity
- Certificate hostname
- Certificate expiry
- Certificate anomalies

Important:

HTTPS does not prove that a website is legitimate.

A phishing website can use a valid HTTPS certificate.

---

## Detection Layer 6 — Website Content

Potential signals:

- Password collection
- OTP collection
- Financial information collection
- UPI PIN requests
- Banking impersonation
- Fake KYC
- Fake payment requests
- Urgency
- Threat language
- Fake account suspension
- Fake prizes
- Fake delivery fees
- Form action mismatch
- Brand mismatch

The presence of a login form alone is not evidence of maliciousness.

Context and domain identity must be evaluated.

---

## Detection Layer 7 — Redirect Analysis

Detect:

- Redirect chains
- Redirect count
- Cross-domain jumps
- Redirect loops
- Short-link destinations
- Suspicious final destinations
- Brand mismatches

Example:

```text
short-link
    ↓
tracking-domain
    ↓
redirect-domain
    ↓
fake-bank-login
```

The final destination matters more than the first URL.

Never blindly fetch arbitrary URLs without a properly isolated and security-reviewed infrastructure.

---

## Detection Layer 8 — Community Intelligence

Analyze:

- Number of unique reports
- Report timestamps
- Confirmed reports
- Reporter reputation
- Report evidence
- False reports
- Similar domains
- Threat category

Protect against malicious mass-reporting.

---

# 8. RISK SCORE AND VERDICT MODEL

The score must be explainable and must not pretend to be a statistically validated probability.

Example conceptual scoring:

| Signal | Possible weight |
|---|---:|
| Confirmed phishing threat | +100 |
| Confirmed malware | +100 |
| Strong brand impersonation | +35 |
| Credential collection with domain mismatch | +35 |
| Confirmed fraudulent community reports | +60 |
| Recently registered domain | +20 |
| Suspicious redirect chain | +20 |
| Suspicious URL structure | +10 |
| Invalid TLS certificate | +15 |
| Official-domain verification | Strong reduction |
| HTTPS | Very small positive technical signal |

These are examples, not final calibrated weights.

The implementation must avoid double-counting correlated signals.

## Separate risk and confidence

**Risk** = How concerning the evidence is.

**Confidence** = How reliable and complete the evidence is.

Examples:

High risk + high confidence:

Confirmed phishing threat-intelligence match.

High risk + medium confidence:

Multiple suspicious signals and strong impersonation indicators.

Low risk + low confidence:

No known threat, but few sources available.

Do not confuse a low risk score with a verified safe website.

---

# 9. VERDICT TAXONOMY

ScamShield should preferably use distinct verdicts.

### MALICIOUS

Confirmed threat intelligence or extremely strong corroborated evidence.

### HIGH RISK

Multiple strong indicators suggesting phishing or fraud.

### SUSPICIOUS

Moderate evidence such as brand impersonation, suspicious redirects, or anomalous domain structure.

### UNVERIFIED

Insufficient information to reliably classify the website.

### NO KNOWN THREAT

Available sources found no known threat, but the website has not necessarily been independently verified.

### TRUSTED

Strong evidence supports the website's legitimate identity, such as a verified official domain.

Verdict precedence must be explicit.

A confirmed malicious threat must never be overridden by a popularity allowlist.

Threat intelligence failures must never silently result in a safe classification.

---

# 10. TEST LAB

A dedicated development/testing interface is required to validate the detection engine.

It should contain approximately 8–10 controlled tests.

### Legitimate baseline websites

- Google
- GitHub
- Microsoft
- Amazon India

### Synthetic brand impersonation tests

Use reserved `.example` domains:

- `sbi-online-kyc-verification.example`
- `hdfc-bank-secure-login.example`
- `phonepe-account-verify.example`

### Simulated threat fixtures

- Synthetic malicious reputation response
- Suspicious redirect chain
- Malformed URL
- Simulated credential-harvesting website indicators

Never browse to actual active malware or phishing links.

The test lab must reuse the real detection engine.

Do not hardcode expected results directly into the UI.

Fixtures must not contaminate:

- Production reputation cache
- Production blocklists
- Community database
- Permanent user data

The test lab must show:

- Expected verdict
- Actual verdict
- Risk score
- Evidence
- Test pass/fail
- Scan duration
- Source of detection
- Run All
- Individual tests
- Reset
- Test progress

---

# 11. BACKEND / SHARED THREAT INTELLIGENCE

The backend is intended to be the common intelligence layer connecting ScamShield's different clients.

Potential responsibilities:

- Reputation lookups
- Threat database
- Community reports
- URL intelligence
- Message analysis
- Threat classification
- Report submission
- API authentication/rate limiting
- Shared intelligence
- Investigation orchestration

The backend API contract must be coordinated between developers.

Do not invent incompatible endpoints or schemas independently.

Any endpoint implemented in one component must be documented and agreed upon.

The extension's reported current reputation endpoint:

```text
/api/v1/reputation/prefix/{prefix}
```

This uses a hash-prefix lookup approach.

The client should send only a partial hash when using a k-anonymity lookup model and verify returned matches locally.

The exact backend implementation and protocol must be reviewed before claiming privacy guarantees.

Never expose private API keys in a browser extension.

---

# 12. DEEP LINK INVESTIGATION

When a user submits a suspicious link, ScamShield may offer deeper investigation.

Potential workflow:

1. User submits URL.
2. ScamShield performs initial analysis.
3. Basic checks identify whether further investigation is warranted.
4. User is asked for consent.
5. If consent is given, a separate investigation system is triggered.
6. The investigation analyzes the URL in a controlled environment.
7. It records relevant evidence.
8. ScamShield returns a readable report.

Potential investigation:

- Redirect chain
- Domain intelligence
- DNS
- TLS
- Website screenshots
- HTML structure
- Suspicious forms
- JavaScript indicators
- Downloads
- Behavioral indicators
- Network requests
- Final destination

## Security warning

GitHub Actions runners are not automatically safe sandboxes for arbitrary malicious websites.

A GitHub Actions-based investigation workflow must not be treated as a complete isolation boundary without a thorough security review.

Never expose secrets or sensitive infrastructure to untrusted website execution.

Do not allow investigated websites to access privileged credentials, internal network services, cloud metadata, repositories, or host infrastructure.

Sandbox design is a security-critical area.

---

# 13. USER EXPERIENCE PRINCIPLES

ScamShield must be usable by non-technical people.

The interface should communicate security clearly.

Avoid:

- Excessive technical jargon
- Unexplained risk scores
- Fake AI confidence
- Fake statistics
- Fake scans
- Fake progress
- Generic AI-generated text
- Unnecessary animations
- Alarmist warnings
- False guarantees

Prefer:

- Clear verdicts
- Explainable evidence
- Actionable recommendations
- Confidence limitations
- Safe defaults
- Simple language
- Professional design
- High contrast
- Accessible UI
- Responsive layouts

The browser extension currently uses a dark cybersecurity-oriented UI.

The product should look premium, trustworthy, modern, and practical.

The UI should not feel like a generic AI-generated cybersecurity dashboard.

---

# 14. MULTILINGUAL SUPPORT

India-first localization is important.

Languages:

- English
- Hindi
- Marathi

Potential future support:

- Hinglish
- Romanized Hindi
- Romanized Marathi
- Other Indian languages

The scam detection engine should understand mixed-language communications where possible.

Examples:

- "KYC update karo warna account band ho jayega"
- "Your parcel is pending payment"
- "Bijli connection aaj cut hoga"
- "UPI refund lene ke liye PIN daalo"
- "Congratulations, you won a prize"

Localization should extend beyond UI labels to actual message interpretation and scam explanations.

---

# 15. PRIVACY & SECURITY PRINCIPLES

ScamShield itself must be trustworthy.

We are building security software. A vulnerable security product defeats its own purpose.

Core principles:

- Data minimization
- No unnecessary browsing history collection
- No keylogging
- No password collection
- No OTP collection
- No unnecessary message retention
- Secure API communication
- No secrets embedded in extensions
- Secure message validation
- Strict permissions
- Offline handling
- Rate limiting
- Abuse prevention
- Secure storage
- Safe URL processing
- SSRF protections for backend investigation
- Isolation of untrusted content
- Transparent consent for deeper investigations
- Honest limitations

Any security claim must be verified.

Do not claim:

- 100% accuracy
- Guaranteed safety
- Complete phishing prevention
- Absolute privacy
- Complete sandbox isolation

unless technically demonstrated and appropriately qualified.

---

# 16. DEVELOPMENT WORKFLOW

The GitHub repository:

https://github.com/VinitSurve/scamshield

The repository has multiple developers working in parallel.

### Workflow

- Each developer works on their own branch.
- No direct pushes to `main`.
- Developers push feature branches.
- Developers open pull requests.
- Repository owner reviews PRs.
- Owner merges into `main`.

Current browser-extension branch:

```text
vinit-browser-extension-mvp
```

The WhatsApp bot is being developed independently by Shubham.

### Collaboration requirements

- Do not overwrite other developers' work.
- Do not modify shared contracts without coordination.
- Avoid conflicts in common files.
- Document API contracts.
- Use separate branches.
- Commit logical changes.
- Review security-sensitive changes carefully.
- Do not merge without owner approval.

---

# 17. HACKATHON STRATEGY

The project is being developed under a limited hackathon timeframe.

Priority order:

1. Functional product
2. Security correctness
3. Detection quality
4. Demonstrable workflow
5. Explainability
6. Reliability
7. UI polish
8. Feature breadth

Do not attempt to implement every possible feature if it compromises the core.

The best hackathon demonstration should show a clear end-to-end scenario.

## Suggested Demo Flow

### Scenario 1 — Suspicious WhatsApp message

Show a message:

"Your electricity connection will be disconnected today. Pay immediately using this link."

Forward it to ScamShield.

Show:

- Scam classification
- Urgency manipulation
- Electricity provider impersonation
- Suspicious payment request
- URL analysis
- Evidence
- Safety recommendations

### Scenario 2 — Browser extension

Visit a legitimate website.

Show:

- Low risk / no known threats
- Evidence
- Domain information

Then demonstrate a synthetic suspicious URL through the scanner/test lab.

Show:

- Brand impersonation
- Domain mismatch
- Suspicious keywords
- Risk score
- Verdict
- Warning

### Scenario 3 — Deeper investigation

Submit a suspicious URL.

Show:

- Initial assessment
- User consent
- Investigation workflow
- Redirect analysis
- Final explanation

Only demonstrate the actual implemented workflow.

Do not fake API responses or pretend live sandbox results are real.

---

# 18. CURRENT STATUS

## Browser extension

Initial implementation has been completed and pushed to:

```text
vinit-browser-extension-mvp
```

Reported implementation:

- Build successful
- TypeScript successful
- 39 unit tests passing
- Popup UI
- Website scanning
- Reputation engine
- Navigation monitoring
- Warning interstitial
- Settings
- Reporting
- Localization

However, the following still require independent validation:

- Real Chrome blocking behavior
- Real website scanning
- API integration
- False positives
- False negatives
- Threat-intelligence correctness
- Redirect tracking
- Gmail functionality
- Community report delivery
- Offline behavior
- Security audit
- Browser-level testing

The implementation report is not a substitute for independent verification.

## WhatsApp bot

Being developed in parallel by Shubham.

The bot and extension should eventually share threat intelligence and backend contracts.

## Backend

Shared backend architecture and integration require coordination between team members.

---

# 19. ROADMAP

## Phase 1 — Hackathon MVP

- Functional WhatsApp scam analysis
- Functional browser extension
- Website scanning
- URL reputation
- Brand impersonation detection
- Suspicious URL analysis
- Threat warnings
- Explainable evidence
- Community reporting
- Controlled test lab
- Shared backend integration
- Demonstrable end-to-end flow

## Phase 2 — Improved Threat Intelligence

- Better reputation data
- Domain age
- DNS intelligence
- TLS intelligence
- Improved redirect analysis
- Community report validation
- False-positive reduction
- Threat intelligence source aggregation

## Phase 3 — Advanced Analysis

- Sandboxed investigations
- Website behavioral analysis
- HTML analysis
- JavaScript analysis
- Download analysis
- Screenshot analysis
- AI-assisted classification with evidence
- Multilingual scam message analysis

## Phase 4 — Platform Expansion

Potential:

- Mobile application
- Android integration
- SMS protection
- Email protection
- Additional browser support
- Other messaging platforms

---

# 20. HOW AI SHOULD BE USED

AI can help with:

- Message interpretation
- Scam pattern classification
- Multilingual analysis
- Summarizing evidence
- Explaining technical findings in simple language
- Categorizing scams
- Identifying social engineering tactics

AI should NOT be the sole authority for:

- Declaring websites safe
- Confirming malware
- Blocking websites without reliable evidence
- Generating fabricated technical evidence
- Inventing threat-intelligence matches

AI-generated conclusions should be grounded in actual extracted evidence.

The ideal architecture is:

**Deterministic security signals + threat intelligence + structured evidence + AI-assisted explanation.**

Not:

**AI sees URL → guesses scam probability → displays random percentage.**

---

# 21. EXPECTED ENGINEERING STANDARDS

Every developer or AI agent working on ScamShield must:

1. Understand the existing architecture before modifying it.
2. Read existing documentation.
3. Inspect current branches and Git status.
4. Respect other developers' work.
5. Avoid rewriting working components unnecessarily.
6. Never fake implementation.
7. Never fake test results.
8. Never fake API responses as live data.
9. Never claim a feature works without verification.
10. Build production-quality code.
11. Add appropriate tests.
12. Handle failures.
13. Document architectural decisions.
14. Prioritize security.
15. Validate the actual browser experience.
16. Explain limitations.
17. Commit changes logically.
18. Push only to the appropriate feature branch.
19. Open a PR rather than merging independently.
20. Provide a factual final delivery report.

When examining a feature, distinguish:

- Implemented
- Tested
- Browser verified
- Backend integrated
- Simulated
- Planned
- Blocked

---

# 22. THE PRODUCT'S DIFFERENTIATOR

ScamShield should not compete by saying:

"We use AI to detect scams."

That statement is generic.

Our differentiation should be:

### Explainable Scam Intelligence

Every result tells users exactly what was detected and why.

### India-First Threat Awareness

Focus on scams targeting Indian users:

- UPI
- KYC
- Banking
- Electricity
- Government services
- Delivery
- Challans
- Job fraud
- Investment fraud

### Multiple Protection Surfaces

WhatsApp bot + browser extension + shared threat intelligence.

### Consent-Based Deep Investigation

Suspicious URLs can be investigated further with user consent.

### Privacy-Aware Detection

Use data minimization and privacy-conscious reputation lookup where technically feasible.

### Actionable Protection

Do not merely identify scams.

Help users understand what to do next.

---

# 23. PROJECT NORTH STAR

The ultimate goal is:

**When a person receives a suspicious message, opens a suspicious link, or encounters a questionable website, ScamShield should help them make a safer decision before they lose money, credentials, or personal information.**

We are building a system that combines:

- Cybersecurity
- Threat intelligence
- Browser protection
- Social engineering detection
- AI-assisted explanation
- Community intelligence
- India-specific scam awareness
- Privacy
- Usability

Every engineering decision should be evaluated against this goal.

---

# 24. INSTRUCTIONS FOR ANY AI OR DEVELOPER RECEIVING THIS CONTEXT

You are working on ScamShield, a cybersecurity product for the MindSprint 2026 hackathon.

Do not assume you are starting from scratch.

First inspect the repository, existing implementation, documentation, branches, and current developer work.

Identify the exact component you are responsible for.

Do not make assumptions about features being implemented or completed merely because they appear in this context.

Prioritize real functionality, security, correctness, maintainability, testability, and explainability.

Challenge flawed assumptions.

If an approach is insecure, technically incorrect, impractical, or unnecessarily complicated, say so clearly and propose a better solution.

Do not blindly agree with the project owner.

Do not manufacture progress.

Do not invent technical evidence.

Do not claim a website is safe simply because no threat was detected.

Do not claim a malicious URL was safely sandboxed unless the isolation mechanism has actually been implemented and verified.

Communicate clearly with the rest of the team.

Respect the Git workflow.

Build ScamShield as a real cybersecurity product—not just a hackathon UI demo.

**The standard is: technically credible, genuinely functional, secure, explainable, demonstrable, and honest about limitations.**