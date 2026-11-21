# Shared Intelligence API Contracts

> **Version:** `v1.0.0`  
> **Protocol:** HTTPS / REST / JSON  
> **Target Consumers:** Browser Extension (Vinit Surve), WhatsApp Bot (Shubham), Web Dashboard

---

## 1. Authentication & Rate Limiting

- **Public Client Endpoints (Extension / Anonymous Lookups):**
  - Authenticated via ephemeral client token or public origin header.
  - Rate limit: 60 requests/minute per IP.
- **Service-to-Service Endpoints (WhatsApp Bot Gateway / Admin Dashboard):**
  - Authenticated via HTTP Header: `Authorization: Bearer <SERVICE_API_KEY>`.
  - Rate limit: 600 requests/minute.

---

## 2. Standardized Error Response Schema

All error responses adhere to RFC 7807 (Problem Details for HTTP APIs):

```json
{
  "type": "https://api.scamshield.org/v1/errors/RATE_LIMIT_EXCEEDED",
  "title": "Rate Limit Exceeded",
  "status": 429,
  "detail": "Too many requests. Quota resets in 42 seconds.",
  "instance": "/api/v1/analyze/url",
  "timestamp": "2026-11-21T11:20:00Z"
}
```

---

## 3. Core API Endpoints

### 3.1 Privacy-Preserving Threat Prefix Lookup
*Used primarily by the Browser Extension to check domains without leaking full URLs.*

- **Endpoint:** `GET /api/v1/reputation/prefix/{prefix}`
- **Path Parameter:** `prefix` (String, exactly 8 hex characters = 32 bits of SHA-256 hash).
- **Response (200 OK):**
```json
{
  "prefix": "3a7f82b1",
  "matches": [
    {
      "full_hash": "3a7f82b19c284701e892d1192e4785f09100a7b14d59a4c82b992134f9a0c102",
      "threat_type": "PHISHING",
      "severity": "HIGH",
      "impersonated_brand": "State Bank of India",
      "reported_count": 38,
      "updated_at": "2026-11-21T10:15:00Z"
    }
  ]
}
```
*Note: If no matches are found for that prefix, `matches` returns an empty array `[]`.*

---

### 3.2 Message Scam Analysis
*Used by the WhatsApp Bot and Browser Extension Email Scanner.*

- **Endpoint:** `POST /api/v1/analyze/message`
- **Request Body:**
```json
{
  "text": "Aapka SBI account aaj band ho jayega. Turant KYC update karein: https://s.id/sbi-kyc-update",
  "language_hint": "auto",
  "channel": "whatsapp",
  "sender_identifier": "+919876543210"
}
```
- **Response (200 OK):**
```json
{
  "verdict": "SCAM",
  "confidence": 0.96,
  "category": "BANKING_KYC_FRAUD",
  "detected_language": "hinglish",
  "risk_severity": "CRITICAL",
  "evidence": [
    "High-urgency coercive language in Hindi/Romanized script ('aaj band ho jayega')",
    "Phishing pattern: Demanding urgent KYC completion via external link",
    "Impersonation of premier financial institution (SBI)",
    "Shortened URL detected: https://s.id/sbi-kyc-update"
  ],
  "extracted_entities": {
    "urls": ["https://s.id/sbi-kyc-update"],
    "upi_ids": [],
    "phone_numbers": []
  },
  "recommended_actions": [
    "Do NOT click the link.",
    "Do NOT share OTP, passwords, or personal details.",
    "SBI never sends account closure notices via unofficial SMS/WhatsApp."
  ],
  "localized_explanation": {
    "en": "This message is a fake KYC scam attempting to steal your banking credentials.",
    "hi": "यह संदेश एक फर्जी KYC घोटाला है जो आपके बैंक खाते का विवरण चुराने का प्रयास कर रहा है।",
    "mr": "हा संदेश एक बनावट KYC घोटाळा आहे जो तुमच्या बँक खात्याची माहिती चोरण्याचा प्रयत्न करत आहे."
  }
}
```

---

### 3.3 Deep Sandboxed URL Investigation Trigger
*Dispatched by WhatsApp Bot (after user consent) or Extension for thorough investigation.*

- **Endpoint:** `POST /api/v1/investigations`
- **Request Body:**
```json
{
  "url": "https://s.id/sbi-kyc-update",
  "priority": "HIGH",
  "caller": "whatsapp_bot",
  "user_consent_granted": true
}
```
- **Response (202 Accepted):**
```json
{
  "investigation_id": "inv_9f81a70c32b",
  "status": "QUEUED",
  "estimated_duration_seconds": 12,
  "status_endpoint": "/api/v1/investigations/inv_9f81a70c32b"
}
```

---

### 3.4 Retrieve Investigation Status & Evidence
- **Endpoint:** `GET /api/v1/investigations/{id}`
- **Response (200 OK - Finished):**
```json
{
  "investigation_id": "inv_9f81a70c32b",
  "status": "COMPLETED",
  "submitted_url": "https://s.id/sbi-kyc-update",
  "final_destination_url": "https://sbi-online-kyc-verification.top/login.php",
  "verdict": "CONFIRMED_MALICIOUS",
  "redirect_hops": [
    {
      "hop_number": 1,
      "url": "https://s.id/sbi-kyc-update",
      "status_code": 302,
      "destination": "https://track.affiliate-network.example/click"
    },
    {
      "hop_number": 2,
      "url": "https://track.affiliate-network.example/click",
      "status_code": 301,
      "destination": "https://sbi-online-kyc-verification.top/login.php"
    }
  ],
  "domain_analysis": {
    "domain": "sbi-online-kyc-verification.top",
    "domain_age_days": 1,
    "registrar": "NameCheap Inc",
    "server_ip": "185.220.101.5",
    "has_valid_tls": true,
    "tls_issuer": "Let's Encrypt"
  },
  "page_analysis": {
    "page_title": "State Bank of India - Official Online Portal",
    "has_credential_harvesting_form": true,
    "impersonated_brand": "State Bank of India",
    "form_action_url": "https://sbi-online-kyc-verification.top/submit_creds.php"
  },
  "sanitized_screenshot_url": "https://evidence.scamshield.org/screenshots/inv_9f81a70c32b.webp"
}
```

---

### 3.5 Submit Community Threat Report
*Used by Extension and WhatsApp bot to submit suspicious URLs, phone numbers, or UPI IDs.*

- **Endpoint:** `POST /api/v1/reports`
- **Request Body:**
```json
{
  "indicator_type": "URL",
  "indicator_value": "https://fake-challan-pay.online",
  "threat_category": "GOVERNMENT_IMPERSONATION",
  "description": "Sent via SMS claiming traffic challan pending",
  "evidence_metadata": {
    "sms_sender": "VK-VCHALN",
    "page_title": "Parivahan eChallan Payment Portal"
  }
}
```
- **Response (201 Created):**
```json
{
  "report_id": "rep_3b110a",
  "status": "RECORDED",
  "current_community_score": 1,
  "message": "Report logged successfully and queued for multi-signal verification."
}
```
