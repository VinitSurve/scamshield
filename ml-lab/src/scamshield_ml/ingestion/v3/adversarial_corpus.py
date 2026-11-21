"""Adversarial Benchmark & Robustness Corpus Generator for ScamShield Dataset v3.

Produces challenging evasion variants and adversarial benign samples:
1. Unicode homoglyphs (Cyrillic / Greek spoofing)
2. Spacing and punctuation manipulation
3. Zero-width character perturbations
4. Brand subdomains on rogue apex domains
5. Legitimate brand domains with login paths (hard negatives)
6. Mixed-script code-switching and abbreviations
7. Adversarial benign messages containing scary keywords ("failed", "blocked", "arrest", "fraud")
"""

from __future__ import annotations

import random
from typing import Any, Dict, List


def generate_adversarial_corpus() -> List[Dict[str, Any]]:
    """Generates an adversarial dataset evaluating model robustness."""
    samples: List[Dict[str, Any]] = []

    # 1. Unicode Homoglyphs & Zero-Width Obfuscation (Scam)
    adv_scams = [
        ("URGENT: Your S\u200bB\u200bI account has been blocked. Update K\u200bY\u200bC at https://sbi-auth.top", "en", "BANKING_KYC", ["https://sbi-auth.top"]),
        ("Alert: Your H\u200cD\u200cF\u200cC bank access is restricted. Verify immediately: https://hdfc-verify.xyz", "en", "BANKING_KYC", ["https://hdfc-verify.xyz"]),
        ("P\u0430ytm (Cyrillic a) reward of Rs. 1,500 waiting. Claim now at https://p\u0430ytm-reward.top", "en", "UPI_FRAUD", ["https://p\u0430ytm-reward.top"]),
        ("U P I collect request received for Rs. 4,999. Accept and enter your secret P I N to get credit.", "en", "UPI_FRAUD", []),
        ("Dear customer, your I_C_I_C_I netbanking is on hold. Click here: https://is.gd/icici-auth", "en", "BANKING_KYC", ["https://is.gd/icici-auth"]),
        ("M-S-E-D-C-L power disconnection notice for tonight 9:30 PM. Call urgent helpline: +91 9876543210", "en", "ELECTRICITY", []),
        ("Digital Arrest warrant issued under Section 420. Video call Inspector Sharma immediately on WhatsApp +91 9123456789.", "en", "DIGITAL_ARREST", []),
        ("K Y C alert: Aapka account band kar diya gaya hai. Turant open karein https://sbi-kyc.click", "hinglish", "BANKING_KYC", ["https://sbi-kyc.click"]),
        ("G P a y cashback Rs 2000! QR code scan karke PIN dalein turant paise lene ke liye.", "hinglish", "QR_CODE_FRAUD", []),
        ("महावितरण वीज तोडणी नोटीस: रात्री ९ वाजता वीज खंडित होईल. त्वरित संपर्क करा: +91 9822334455", "mr", "ELECTRICITY", []),
    ]

    for text, lang, cat, urls in adv_scams:
        samples.append({
            "content": text,
            "content_type": "message",
            "label": "scam",
            "is_scam": 1,
            "category": cat,
            "language": lang,
            "source": "synthetic_adversarial_generator",
            "extracted_urls": urls,
            "extracted_phones": [p for p in ["+91 9876543210", "+91 9123456789", "+91 9822334455"] if p in text],
            "extracted_upis": [],
            "synthetic": True,
            "brand": None,
            "explanation": "Adversarial evasion attempt using zero-width spaces, homoglyphs, or character spacing.",
        })

    # 2. Adversarial Benign Samples (Scary keywords in harmless contexts)
    adv_benigns = [
        ("Alert: Your UPI transaction of Rs. 500 to Swiggy FAILED due to incorrect UPI PIN entered. Your account is secure.", "en", "LEGITIMATE_BANKING"),
        ("Dear Customer, Your debit card was temporarily blocked because 3 incorrect PIN attempts were made at ATM. Visit nearest branch to unblock.", "en", "LEGITIMATE_BANKING"),
        ("Security notice: A new login to your Google Account was detected from Chrome on Windows in Mumbai. If this was you, no action needed.", "en", "LEGITIMATE_SECURITY"),
        ("Police advisory: Beware of fraudsters threatening Digital Arrest over Skype or WhatsApp. Real police never conducts digital arrests.", "en", "LEGITIMATE_GOVT_ADVISORY"),
        ("Bhai, emergency hai! Dost ka accident ho gaya hai hospital me admit hai. Jaldi se 2000 bhejde GPay pe please.", "hinglish", "LEGITIMATE_PERSONAL"),
        ("Aapka electricity bill payment failed ho gaya tha transaction timeout ki wajah se. Paise kat gaye ho toh 24h me refund ho jayenge.", "hinglish", "LEGITIMATE_UTILITY"),
        ("सूचना: महावितरणच्या नावाने येणाऱ्या खोट्या वीजबिलांच्या मेसेजवर विश्वास ठेवू नका. सायबर गुन्ह्यांपासून सावध राहा.", "mr", "LEGITIMATE_GOVT_ADVISORY"),
        ("आई, काळजी करू नकोस. मी सुरक्षित पोहोचलो आहे. प्रवासात फोन बंद होता चार्जिंग संपल्यामुळे.", "mr", "LEGITIMATE_PERSONAL"),
        ("https://retail.onlinesbi.sbi/personal/sbi_home.html", "en", "LEGITIMATE_PORTAL"),
        ("https://netbanking.hdfcbank.com/netbanking/CCLogin.html", "en", "LEGITIMATE_PORTAL"),
    ]

    for text, lang, cat in adv_benigns:
        samples.append({
            "content": text,
            "content_type": "url" if text.startswith("http") else "message",
            "label": "legitimate",
            "is_scam": 0,
            "category": cat,
            "language": lang,
            "source": "synthetic_adversarial_generator",
            "extracted_urls": [text] if text.startswith("http") else [],
            "extracted_phones": [],
            "extracted_upis": [],
            "synthetic": True,
            "brand": None,
            "explanation": "Adversarial benign trap message containing fraud/urgency terminology in legitimate context.",
        })

    return samples
