# ScamShield WhatsApp Security Bot

> **Think Before You Click.**  
> Proactive, multi-channel cyber threat intelligence bot protecting WhatsApp users against phishing links, fake banking KYC lures, UPI fraud, and deceptive screenshots.

---

## 1. Operating Modes

The ScamShield WhatsApp Bot operates in two distinct modes:

### A. Demo Mode (`WHATSAPP_MODE=demo`) — Default for Hackathon & Local Verification
- Runs out of the box without requiring Meta Business verification or paid Cloud API phone numbers.
- Uses the **exact same ScamShield analysis engine** as the live bot:
  - Text & URL message threat scanning.
  - Social engineering & urgency pressure detection.
  - Image OCR & QR code indicator extraction.
  - Reputation service cross-checks (`ReputationService.evaluateUrl`).
  - User consent for deeper threat investigation.
- Full real-time interactive simulation is directly accessible from the **ScamShield Chrome Extension Popup ("Open WhatsApp Bot Simulator")**.

### B. Meta WhatsApp Cloud API Mode (`WHATSAPP_MODE=cloud_api`)
- Official Meta WhatsApp Business Platform integration.
- Connects to your Meta App ID, System User Access Token, and verified Phone Number ID.
- Features:
  - Meta Webhook challenge verification (`GET /webhook`).
  - Real-time incoming webhook processing (`POST /webhook`).
  - Strict SSRF (Server-Side Request Forgery) protection on media attachments: only downloads from verified Meta CDN origins (`lookaside.fbsbx.com`, `*.whatsapp.net`).
  - Message deduplication tracking to prevent re-processing retried webhooks.
  - HMAC SHA-256 webhook payload signature verification (`X-Hub-Signature-256`).

---

## 2. Configuration (`.env`)

Create `.env` using `.env.example`:

```env
WHATSAPP_MODE=demo
WHATSAPP_ENABLED=true
PORT=3001

# Meta Cloud API Credentials (Required ONLY for live cloud_api mode)
WHATSAPP_ACCESS_TOKEN=EAAG...
WHATSAPP_PHONE_NUMBER_ID=108291829...
WHATSAPP_VERIFY_TOKEN=scamshield_webhook_secret_verify_token_2026
WHATSAPP_APP_SECRET=your_meta_app_secret

# Threat Scanner Backend URL
SCAMSHIELD_API_URL=https://api.scamshield.org
```

---

## 3. Quick Start & Execution

```bash
# Install dependencies
npm install

# Run automated test suite
npm test

# Build TypeScript
npm run build

# Start server
npm start
```

Endpoints:
- `GET /health` — Service healthcheck and active operating mode.
- `GET /webhook` — Meta Webhook verification handshake.
- `POST /webhook` — Inbound WhatsApp event handler.
