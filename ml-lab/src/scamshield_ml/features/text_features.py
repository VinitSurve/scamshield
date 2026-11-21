"""Multilingual Text & Indian Scam Heuristic Feature Extractor."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Set

URGENCY_KEYWORDS = {
    "urgent", "urgently", "immediately", "blocked", "suspended",
    "disconnect", "disconnected", "cutoff", "cut", "expire",
    "expired", "today", "tonight", "24 hours", "turant", "jaldi",
    "aaj", "tatkal", "fauran", "taatkal"
}

FINANCIAL_KEYWORDS = {
    "rs", "inr", "₹", "cashback", "lottery", "won", "prize",
    "reward", "points", "refund", "credited", "debited", "lakh",
    "crore", "deposit", "winner", "bonus"
}

KYC_KEYWORDS = {
    "kyc", "pan", "aadhaar", "document", "re-kyc", "identity",
    "verification", "update kyc", "khata", "bank account", "unfreeze"
}

CREDENTIAL_KEYWORDS = {
    "otp", "pin", "upi pin", "cvv", "password", "passcode", "code",
    "screen share", "anydesk", "teamviewer", "rustdesk"
}


class TextFeatureExtractor:
    """Extracts domain-specific cybersecurity and Indian linguistic features from text."""

    @staticmethod
    def extract_heuristics(text: str) -> Dict[str, Any]:
        lower = text.lower()
        words = set(re.findall(r"\w+", lower))

        has_urgency = 1 if any(w in lower for w in URGENCY_KEYWORDS) else 0
        has_financial = 1 if any(w in lower for w in FINANCIAL_KEYWORDS) else 0
        has_kyc = 1 if any(w in lower for w in KYC_KEYWORDS) else 0
        has_credential = 1 if any(w in lower for w in CREDENTIAL_KEYWORDS) else 0

        # Extract entities
        urls = re.findall(r"https?://[^\s<>'\"{}|\\^`[\]]+|\b[a-zA-Z0-9-]{2,63}\.(?:top|xyz|in|com|org|net|gd|ly)\b[^\s<>'\"{}|\\^`[\]]*", text)
        phones = re.findall(r"(?:(?:\+91|91|0)[-.\s]?)?[6-9]\d{4}[-.\s]?\d{5}\b", text)
        upis = re.findall(r"\b[a-zA-Z0-9.\-_]{2,64}@[a-zA-Z]{2,32}\b", text)

        # Filter upis from emails
        upis = [u for u in upis if not any(u.endswith(dom) for dom in ("@gmail.com", "@yahoo.com", "@outlook.com", "@example.com"))]

        return {
            "has_urgency": has_urgency,
            "has_financial": has_financial,
            "has_kyc": has_kyc,
            "has_credential": has_credential,
            "url_count": len(urls),
            "phone_count": len(phones),
            "upi_count": len(upis),
            "char_length": len(text),
            "word_count": len(words),
            "extracted_urls": urls,
            "extracted_phones": phones,
            "extracted_upis": upis,
        }
