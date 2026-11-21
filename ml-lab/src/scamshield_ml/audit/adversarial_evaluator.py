"""Phase 6: Adversarial & Robustness Stress-Testing Engine for ScamShield ML Lab.

Evaluates the production ensemble against 18 distinct evasion and perturbation attacks:
- Typo and misspelling injection
- Character spacing evasion
- Unicode homoglyphs and Cyrillic lookalikes
- Zero-width character injection
- URL obfuscation (hex/IP/subdomain masquerading)
- Shortened URLs
- Punctuation stripping
- Informal language and colloquial code-switching
- Emoji flooding
- Message truncation and fragmentation
- Hard benign messages with high keyword overlap
- Subtle scams lacking overt triggers
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List

import numpy as np

from scamshield_ml.models.ensemble import EnsembleScamModel


ADVERSARIAL_TESTS: List[Dict[str, Any]] = [
    # 1. Misspellings / Typo Injection
    {
        "id": "ADV-TYPO-01",
        "attack_type": "TYPO_INJECTION",
        "expected": "SCAM",
        "text": "Deaar Customr, your SBI bank acont has bean suspendd. Updat KYC immidiately: https://sbi-alert-desk.top",
        "notes": "Common typos introduced in 'Dear', 'Customer', 'account', 'been', 'suspended', 'immediately'",
    },
    {
        "id": "ADV-TYPO-02",
        "attack_type": "TYPO_INJECTION",
        "expected": "SCAM",
        "text": "BESC0M: Urgnt! Tumhari bijli line aaj rat kat jaygi unpaid bil ki vajah se. Call kare power ofiser 9876543210",
        "notes": "Typos in BESCOM (with zero), Urgnt, rat, bil, ofiser",
    },

    # 2. Spacing Manipulation
    {
        "id": "ADV-SPACING-01",
        "attack_type": "SPACING_MANIPULATION",
        "expected": "SCAM",
        "text": "D e a r   C u s t o m e r   y o u r   b a n k   a c c o u n t   b l o c k e d   u p d a t e   K Y C   n o w   https://is.gd/sbiAlert",
        "notes": "Spaced out letters to evade tokenizers",
    },
    {
        "id": "ADV-SPACING-02",
        "attack_type": "SPACING_MANIPULATION",
        "expected": "SCAM",
        "text": "Your P-A-N card is not linked with S-B-I. Click h-t-t-p-s-:-/-/-s-b-i-.-t-o-p to verify.",
        "notes": "Hyphenated spacing across keywords",
    },

    # 3. Unicode Homoglyphs & Lookalikes
    {
        "id": "ADV-HOMOGLYPH-01",
        "attack_type": "UNICODE_HOMOGLYPH",
        "expected": "SCAM",
        "text": "Deаr Custоmer, yоur bаnk ассоunt KYC hаs expired. Please verify аt https://sbi-kyc.top",
        "notes": "Cyrillic а (U+0430) and о (U+043E) substituted for Latin a and o",
    },
    {
        "id": "ADV-HOMOGLYPH-02",
        "attack_type": "UNICODE_HOMOGLYPH",
        "expected": "SCAM",
        "text": "HDFC​Bank​Alert:​Your​netbanking​is​suspended.​Visit​https://hdfc-verify.top",
        "notes": "Zero-width spaces (U+200B) inserted between words to break whitespace tokenization",
    },

    # 4. URL Obfuscation & Brand Subdomain Masquerading
    {
        "id": "ADV-URL-01",
        "attack_type": "URL_OBFUSCATION",
        "expected": "SCAM",
        "text": "Your SBI account is blocked. Verify at https://onlinesbi.sbi.co.in.auth-update-kyc.top/login",
        "notes": "Legitimate brand domain used as subdomains on an attacker-controlled .top TLD",
    },
    {
        "id": "ADV-URL-02",
        "attack_type": "URL_OBFUSCATION",
        "expected": "SCAM",
        "text": "Income tax refund of Rs 14,200 approved. Confirm bank account details at http://142.250.190.46/refund",
        "notes": "Raw IP address instead of domain name",
    },

    # 5. Shortened URLs
    {
        "id": "ADV-SHORT-URL-01",
        "attack_type": "SHORTENED_URL",
        "expected": "SCAM",
        "text": "Dear user your package delivery address is incomplete. Resolve immediately: https://bit.ly/3x9Zq8P",
        "notes": "Bitly shortened link concealing phishing payload",
    },
    {
        "id": "ADV-SHORT-URL-02",
        "attack_type": "SHORTENED_URL",
        "expected": "SCAM",
        "text": "You received Rs. 2,500 cashback voucher. Click to transfer to bank: https://tinyurl.com/cb-reward-claim",
        "notes": "TinyURL link used for financial cashback lure",
    },

    # 6. Punctuation Stripping
    {
        "id": "ADV-PUNCT-01",
        "attack_type": "PUNCTUATION_STRIPPING",
        "expected": "SCAM",
        "text": "dear customer your icici bank account has been suspended please update your kyc click link activate your bank account http is gd J9gaHq icicibank kyc",
        "notes": "All punctuation, colons, slashes removed",
    },

    # 7. Informal Slang & Code-Switching
    {
        "id": "ADV-SLANG-01",
        "attack_type": "COLLOQUIAL_SLANG",
        "expected": "SCAM",
        "text": "Arey bhai sun tera HDFC account lock ho gaya yaar, jaldi se ye link kholke theek karle nahi to fine padega: http://hdfc-unlock.xyz",
        "notes": "Extreme informal Hinglish slang",
    },
    {
        "id": "ADV-SLANG-02",
        "attack_type": "COLLOQUIAL_SLANG",
        "expected": "SCAM",
        "text": "Bhava tuzha light bill baki ahe aaj ratri light ghalavnart te lok. Ya number var call kar 9876543210",
        "notes": "Colloquial Marathi slang (Bhava)",
    },

    # 8. Emoji Flooding
    {
        "id": "ADV-EMOJI-01",
        "attack_type": "EMOJI_FLOODING",
        "expected": "SCAM",
        "text": "🚨🚨 URGENT NOTICE 🚨🚨 ⚠️ YOUR SBI BANK ACCOUNT HAS BEEN BLOCKED ⚠️ 🔴 CLICK HERE TO ACTIVATE: https://sbi-reactivate.top 💳💰💸",
        "notes": "Heavy emoji usage typically seen in WhatsApp forwards",
    },

    # 9. Message Fragmentation
    {
        "id": "ADV-FRAG-01",
        "attack_type": "MESSAGE_FRAGMENTATION",
        "expected": "SCAM",
        "text": "Part 1/2: Your bank KYC has been suspended.",
        "notes": "Fragmented SMS part 1",
    },
    {
        "id": "ADV-FRAG-02",
        "attack_type": "MESSAGE_FRAGMENTATION",
        "expected": "SCAM",
        "text": "Part 2/2: Click link to verify immediately http://kyc-desk.top",
        "notes": "Fragmented SMS part 2 containing link",
    },

    # 10. Long Benign Containing Suspicious Keywords
    {
        "id": "ADV-BENIGN-KEYWORDS-01",
        "attack_type": "BENIGN_WITH_SUSPICIOUS_KEYWORDS",
        "expected": "LEGITIMATE",
        "text": "Dear Customer, please be cautious about fraudulent SMS messages claiming your account or electricity connection is blocked due to pending KYC or unpaid bills. Official bank representatives or power utility officers will never ask you to call private 10-digit mobile numbers or click shortened web links. If you receive such suspicious communication, report it to the National Cyber Crime portal at cybercrime.gov.in or call 1930 immediately.",
        "notes": "Long advisory containing words 'blocked', 'KYC', 'electricity', 'unpaid bills', 'SMS', 'links'",
    },
    {
        "id": "ADV-BENIGN-KEYWORDS-02",
        "attack_type": "BENIGN_WITH_SUSPICIOUS_KEYWORDS",
        "expected": "LEGITIMATE",
        "text": "SBI Alert: Your request for unblocking netbanking user ID has been completed successfully through your registered branch. Your temporary password was dispatched. If you did not initiate this change, please block your access immediately by calling 1800112211 or visiting onlinesbi.sbi.",
        "notes": "Legitimate message with 'unblocking', 'blocked', 'netbanking', 'password'",
    },

    # 11. Subtle Scam With No Obvious Keywords
    {
        "id": "ADV-SUBTLE-SCAM-01",
        "attack_type": "SUBTLE_SCAM_NO_KEYWORDS",
        "expected": "SCAM",
        "text": "Hey, I uploaded our group trip photographs to the cloud gallery for you to see: http://shared-drive-photos.top/album",
        "notes": "Social engineering lure with no financial or urgency trigger words",
    },
    {
        "id": "ADV-SUBTLE-SCAM-02",
        "attack_type": "SUBTLE_SCAM_NO_KEYWORDS",
        "expected": "SCAM",
        "text": "Good morning. Please review the attached contract document before our afternoon client conference: http://doc-viewer-online.top/file",
        "notes": "Office worker phishing without urgency or banking words",
    },

    # 12. Legitimate Messages Containing URLs
    {
        "id": "ADV-BENIGN-URL-01",
        "attack_type": "BENIGN_WITH_URL",
        "expected": "LEGITIMATE",
        "text": "Your SBI Life insurance policy renewal premium is due on 30-Nov-2026. Pay safely online using official portal https://www.sbilife.co.in or SBI Yono app.",
        "notes": "Legitimate banking insurance notification containing an authentic URL",
    },
    {
        "id": "ADV-BENIGN-URL-02",
        "attack_type": "BENIGN_WITH_URL",
        "expected": "LEGITIMATE",
        "text": "MSEDCL Consumer: Download your digitally signed electricity bill for consumer no 0284910291 from https://wss.mahadiscom.in/wss/wss. Mahavitaran.",
        "notes": "Legitimate utility notification with direct portal URL",
    },

    # 13. Legitimate Financial & Debit Messages
    {
        "id": "ADV-BENIGN-FINANCIAL-01",
        "attack_type": "BENIGN_FINANCIAL",
        "expected": "LEGITIMATE",
        "text": "Dear Customer, INR 45,000.00 debited from a/c **9102 on 22-NOV-26 towards MUTUAL FUND SIP via NACH mandate. Avail Bal: INR 1,24,091.20.",
        "notes": "Standard high-value mutual fund investment debit alert",
    },
    {
        "id": "ADV-BENIGN-FINANCIAL-02",
        "attack_type": "BENIGN_FINANCIAL",
        "expected": "LEGITIMATE",
        "text": "HDFC Bank: Salary of Rs. 84,500 credited to account ending 2019 by INFOSYS LIMITED. Available balance: Rs. 92,100.",
        "notes": "Standard monthly salary credit notification",
    },
]


def audit_adversarial_robustness() -> Dict[str, Any]:
    base_dir = Path(__file__).resolve().parent.parent.parent.parent
    models_dir = base_dir / "artifacts" / "models"

    ensemble = EnsembleScamModel()
    ensemble.load(str(models_dir / "ensemble.joblib"))

    results: Dict[str, Any] = {
        "total_adversarial_samples": len(ADVERSARIAL_TESTS),
        "overall_accuracy_pct": 0.0,
        "attack_breakdown": {},
        "evasion_failures": [],
    }

    texts = [t["text"] for t in ADVERSARIAL_TESTS]
    y_true = np.array([1 if t["expected"] == "SCAM" else 0 for t in ADVERSARIAL_TESTS])

    preds = ensemble.predict_batch(texts)
    y_pred = np.array([p.is_scam for p in preds])
    y_probs = np.array([p.scam_probability for p in preds])

    total_correct = int(np.sum(y_true == y_pred))
    results["overall_accuracy_pct"] = round(total_correct / len(ADVERSARIAL_TESTS) * 100, 2)

    attack_types = sorted(list(set(t["attack_type"] for t in ADVERSARIAL_TESTS)))
    for atk in attack_types:
        sub_indices = [i for i, t in enumerate(ADVERSARIAL_TESTS) if t["attack_type"] == atk]
        sub_true = y_true[sub_indices]
        sub_pred = y_pred[sub_indices]
        correct = int(np.sum(sub_true == sub_pred))
        total = len(sub_indices)
        results["attack_breakdown"][atk] = {
            "total": total,
            "correct": correct,
            "accuracy_pct": round(correct / total * 100, 2),
            "robustness": "ROBUST" if correct == total else "VULNERABLE",
        }

    for i, t in enumerate(ADVERSARIAL_TESTS):
        if y_true[i] != y_pred[i]:
            results["evasion_failures"].append({
                "id": t["id"],
                "attack_type": t["attack_type"],
                "expected": t["expected"],
                "predicted": "SCAM" if y_pred[i] == 1 else "LEGITIMATE",
                "scam_probability": round(float(y_probs[i]), 4),
                "notes": t["notes"],
                "text": t["text"],
            })

    return results


if __name__ == "__main__":
    res = audit_adversarial_robustness()
    print(json.dumps(res, indent=2))
