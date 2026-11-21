"""Phase 4: Feature Shortcut Auditor & Controlled Counterfactual Testing."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Tuple

import joblib
import numpy as np

from scamshield_ml.models.ensemble import EnsembleScamModel
from scamshield_ml.models.logistic_regression import LogisticRegressionScamModel


def audit_feature_shortcuts() -> Dict[str, Any]:
    base_dir = Path(__file__).resolve().parent.parent.parent.parent
    models_dir = base_dir / "artifacts" / "models"

    results: Dict[str, Any] = {
        "top_scam_features": [],
        "top_legit_features": [],
        "placeholder_artifacts": [],
        "counterfactual_tests": [],
        "counterfactual_summary": {},
    }

    # 1. Inspect Logistic Regression Weights
    log_dict = joblib.load(models_dir / "logistic.joblib")
    vectorizer = log_dict["vectorizer"]
    classifier = log_dict["classifier"]

    feature_names = vectorizer.get_feature_names_out()
    coefs = classifier.coef_[0]

    top_scam_idx = np.argsort(coefs)[::-1][:30]
    top_legit_idx = np.argsort(coefs)[:30]

    results["top_scam_features"] = [
        {"feature": feature_names[i], "weight": round(float(coefs[i]), 4)}
        for i in top_scam_idx
    ]

    results["top_legit_features"] = [
        {"feature": feature_names[i], "weight": round(float(coefs[i]), 4)}
        for i in top_legit_idx
    ]

    # Check for placeholder/synthetic artifacts
    artifacts_found = []
    for i in np.argsort(np.abs(coefs))[::-1][:150]:
        feat = feature_names[i]
        if feat in ("xyz", "is", "gd", "is gd", "top", "bit", "ly", "bit ly", "com", "http", "https"):
            artifacts_found.append({
                "feature": feat,
                "weight": round(float(coefs[i]), 4),
                "type": "URL_OR_SYNTHETIC_PLACEHOLDER_ARTIFACT",
            })
    results["placeholder_artifacts"] = artifacts_found

    # 2. Counterfactual Battery
    ensemble = EnsembleScamModel()
    ensemble.load(str(models_dir / "ensemble.joblib"))

    counterfactual_suite = [
        # Type 1: Scam intent preserved, but classic keywords ("urgent", "blocked", "kyc", "suspended") removed
        {
            "test_id": "CF-SCAM-NO-KEYWORDS-01",
            "type": "KEYWORD_REMOVAL_SCAM_PRESERVED",
            "original_label": "SCAM",
            "description": "Phishing lure asking to update profile via link without words 'urgent', 'blocked', 'kyc'",
            "text": "Dear user, please review and update your banking contact profile for online services at http://secure-bank-update.xyz",
        },
        {
            "test_id": "CF-SCAM-NO-KEYWORDS-02",
            "type": "KEYWORD_REMOVAL_SCAM_PRESERVED",
            "original_label": "SCAM",
            "description": "Electricity scam without 'disconnected' or 'urgent', asking to call manager",
            "text": "Regarding your electricity meter bill from previous month, kindly discuss with our power executive at 9876543210.",
        },
        # Type 2: Legitimate messages containing scam keywords ("urgent", "blocked", "kyc", "verify", "pin")
        {
            "test_id": "CF-BENIGN-SCAM-WORDS-01",
            "type": "BENIGN_WITH_SCAM_WORDS",
            "original_label": "LEGITIMATE",
            "description": "Legitimate bank notification confirming KYC was completed at branch",
            "text": "Dear Customer, your KYC verification was successfully completed at our branch. Your account is active. Do not share your OTP or PIN with anyone.",
        },
        {
            "test_id": "CF-BENIGN-SCAM-WORDS-02",
            "type": "BENIGN_WITH_SCAM_WORDS",
            "original_label": "LEGITIMATE",
            "description": "Legitimate security alert stating card was blocked upon user's request",
            "text": "Your SBI Debit Card ending in 4021 has been blocked as per your request. If not requested by you, call 1800112211.",
        },
        {
            "test_id": "CF-BENIGN-SCAM-WORDS-03",
            "type": "BENIGN_WITH_SCAM_WORDS",
            "original_label": "LEGITIMATE",
            "description": "Legitimate utility reminder about regular bill payment due date",
            "text": "Dear MSEDCL consumer, your electricity bill of Rs. 1420 is due on 25-Nov. Avoid late charges by paying via mahadiscom portal.",
        },
        {
            "test_id": "CF-BENIGN-SCAM-WORDS-04",
            "type": "BENIGN_WITH_SCAM_WORDS",
            "original_label": "LEGITIMATE",
            "description": "Legitimate UPI payment confirmation containing refund word",
            "text": "Refund of Rs. 499 from Swiggy has been credited to your HDFC Bank account via UPI ref 492019284102.",
        },
        # Type 3: Brand substitutions (replacing SBI with small cooperative bank or unknown entity)
        {
            "test_id": "CF-BRAND-SUBST-01",
            "type": "BRAND_SUBSTITUTION",
            "original_label": "SCAM",
            "description": "KYC scam replacing SBI with Saraswat Bank",
            "text": "Dear Customer, your Saraswat Bank account has been suspended. Update KYC at https://saraswat-portal-verify.top",
        },
        {
            "test_id": "CF-BRAND-SUBST-02",
            "type": "BRAND_SUBSTITUTION",
            "original_label": "SCAM",
            "description": "KYC scam replacing SBI with unknown cooperative credit society",
            "text": "Dear Member, your Janaseva Credit Society account will be blocked today due to pending KYC. Verify immediately: https://janaseva-kyc.xyz",
        },
        # Type 4: URL variations (IP address, clean domain with phishing path, shortened link)
        {
            "test_id": "CF-URL-IP-01",
            "type": "URL_VARIATION",
            "original_label": "SCAM",
            "description": "Scam pointing to raw IP address instead of domain",
            "text": "Your HDFC netbanking is suspended. Click to reactivate: http://192.168.10.45/hdfc/login",
        },
        {
            "test_id": "CF-URL-CLEAN-TLD-01",
            "type": "URL_VARIATION",
            "original_label": "SCAM",
            "description": "Scam using .org or .edu domain",
            "text": "SBI Alert: Your account KYC has lapsed. Update at http://student-welfare.org/sbi-verify to avoid penalty.",
        },
        # Type 5: Cross-lingual & Romanized variants with informal phrasing
        {
            "test_id": "CF-LANG-INFORMAL-01",
            "type": "INFORMAL_ROMANIZED",
            "original_label": "SCAM",
            "description": "Hinglish informal courier parcel scam",
            "text": "Bhai tera parcel deliver nahi ho paya address adhura tha. Jaldi se update karle nahi to return ho jayega: http://dtdc-redelivery.xyz",
        },
        {
            "test_id": "CF-LANG-INFORMAL-02",
            "type": "INFORMAL_ROMANIZED",
            "original_label": "SCAM",
            "description": "Marathi informal job scam",
            "text": "Ghari basun roj 2000 te 3000 kamva fakt youtube video like karun. Sampark kara whatsapp var 9876543210.",
        },
        # Type 6: Adversarial spacing & homoglyphs
        {
            "test_id": "CF-OBFUSCATION-01",
            "type": "SPACING_OBFUSCATION",
            "original_label": "SCAM",
            "description": "Spacing inserted in keywords: K Y C, b l o c k e d",
            "text": "Dear user your S B I account is b l o c k e d. Complete your K Y C now at http://sbi-alert.top",
        },
        {
            "test_id": "CF-OBFUSCATION-02",
            "type": "HOMOGLYPH_SUBSTITUTION",
            "original_label": "SCAM",
            "description": "Cyrillic homoglyphs replacing 'a' and 'o'",
            "text": "Deаr Custоmer, yоur bаnk ассоunt KYC is suspended. Verify аt http://icici-verify.xyz",
        },
    ]

    cf_results = []
    flips_or_errors = 0

    for test in counterfactual_suite:
        pred = ensemble.predict_one(test["text"])
        predicted_label = "SCAM" if pred.is_scam == 1 else "LEGITIMATE"
        is_correct = predicted_label == test["original_label"]

        if not is_correct:
            flips_or_errors += 1

        cf_results.append({
            "test_id": test["test_id"],
            "type": test["type"],
            "expected_label": test["original_label"],
            "predicted_label": predicted_label,
            "scam_probability": round(pred.scam_probability, 4),
            "correct": is_correct,
            "description": test["description"],
            "text": test["text"],
        })

    results["counterfactual_tests"] = cf_results
    results["counterfactual_summary"] = {
        "total_counterfactuals": len(counterfactual_suite),
        "total_failures": flips_or_errors,
        "failure_rate_pct": round(flips_or_errors / len(counterfactual_suite) * 100, 2),
        "accuracy_pct": round((len(counterfactual_suite) - flips_or_errors) / len(counterfactual_suite) * 100, 2),
        "failures_by_type": dict(Counter(t["type"] for t in cf_results if not t["correct"])),
    }

    return results


if __name__ == "__main__":
    res = audit_feature_shortcuts()
    print(json.dumps(res, indent=2))
