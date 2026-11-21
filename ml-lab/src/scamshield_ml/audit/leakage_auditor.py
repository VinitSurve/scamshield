"""Phase 2: Deep Leakage Auditor (Exact, Near-Duplicate, Entity, and Structural Template Leakage)."""

from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple
from urllib.parse import urlparse

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity


def normalize_content(text: str) -> str:
    cleaned = re.sub(r"[^\w\s]", " ", text.lower())
    return " ".join(cleaned.split())


def extract_template_signature(text: str) -> str:
    """Abstracts variable slots to extract the underlying template signature."""
    s = text

    # URLs
    s = re.sub(r"https?://[^\s<>\"'()]+", "<URL>", s)
    s = re.sub(r"\b(?:bit\.ly|is\.gd|tinyurl\.com|t\.co|wa\.me)/[^\s]+", "<URL>", s)

    # Phone numbers
    s = re.sub(r"(?:\+91|0)?[-\s]?[6-9]\d{4}[-\s]?\d{5}", "<PHONE>", s)
    s = re.sub(r"\b\d{10}\b", "<PHONE>", s)

    # UPI Handles
    s = re.sub(r"[\w\.\-]+@(okhdfcbank|okaxis|oksbi|okicici|paytm|ybl|apl|upi|axl|ibl)", "<UPI>", s, flags=re.I)

    # Currency amounts
    s = re.sub(r"[₹RsINR\.]+\s*\d+[\d,]*", "<AMOUNT>", s, flags=re.I)
    s = re.sub(r"\b\d+[\d,]*\s*(?:rs|rupees|inr)\b", "<AMOUNT>", s, flags=re.I)

    # Codes, OTPs, Reference Numbers, Account Numbers
    s = re.sub(r"\b(?<!\w)\d{4,8}(?!\w)\b", "<CODE>", s)
    s = re.sub(r"\bXX+\d{3,4}\b", "<ACCT_MASK>", s, flags=re.I)

    # Dates and Times
    s = re.sub(r"\b\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b", "<DATE>", s)
    s = re.sub(r"\b\d{1,2}:\d{2}(?::\d{2})?\s*(?:am|pm)?\b", "<TIME>", s, flags=re.I)

    # Named entities: Banks
    s = re.sub(r"\b(?:SBI|State Bank of India|HDFC|ICICI|Axis|PNB|Kotak|Bank of Baroda|Canara Bank|Union Bank)\b", "<BANK>", s, flags=re.I)

    # Named entities: Utilities
    s = re.sub(r"\b(?:MSEDCL|BESCOM|TNEB|Adani Electricity|Tata Power|UPPCL|Mahavitaran)\b", "<UTILITY>", s, flags=re.I)

    # Named entities: Courier
    s = re.sub(r"\b(?:India Post|BlueDart|DTDC|Delhivery|FedEx|Amazon|Flipkart)\b", "<COURIER>", s, flags=re.I)

    # Clean whitespace and lowercase
    cleaned = re.sub(r"[^\w<>]+", " ", s.lower())
    return " ".join(cleaned.split())


def audit_leakage() -> Dict[str, Any]:
    base_dir = Path(__file__).resolve().parent.parent.parent.parent
    data_dir = base_dir / "data" / "processed"

    with open(data_dir / "train.json", "r", encoding="utf-8") as f:
        train_samples = json.load(f)
    with open(data_dir / "val.json", "r", encoding="utf-8") as f:
        val_samples = json.load(f)
    with open(data_dir / "test.json", "r", encoding="utf-8") as f:
        test_samples = json.load(f)

    results: Dict[str, Any] = {
        "exact_leakage": {},
        "normalized_leakage": {},
        "entity_leakage": {},
        "cosine_similarity_audit": {},
        "structural_template_leakage": {},
    }

    # 1. Exact Leakage
    train_raw = {s["content"] for s in train_samples}
    val_raw = {s["content"] for s in val_samples}
    test_raw = {s["content"] for s in test_samples}

    results["exact_leakage"] = {
        "train_val_exact_overlap": len(train_raw.intersection(val_raw)),
        "train_test_exact_overlap": len(train_raw.intersection(test_raw)),
        "val_test_exact_overlap": len(val_raw.intersection(test_raw)),
    }

    # 2. Normalized Leakage
    train_norm = {normalize_content(s["content"]): s["sample_id"] for s in train_samples}
    val_norm = {normalize_content(s["content"]): s["sample_id"] for s in val_samples}
    test_norm = {normalize_content(s["content"]): s["sample_id"] for s in test_samples}

    tr_val_norm_overlap = set(train_norm.keys()).intersection(val_norm.keys())
    tr_test_norm_overlap = set(train_norm.keys()).intersection(test_norm.keys())
    val_test_norm_overlap = set(val_norm.keys()).intersection(test_norm.keys())

    results["normalized_leakage"] = {
        "train_val_norm_overlap": len(tr_val_norm_overlap),
        "train_test_norm_overlap": len(tr_test_norm_overlap),
        "val_test_norm_overlap": len(val_test_norm_overlap),
    }

    # 3. Entity Leakage (URLs, Phones, UPIs)
    def extract_entities(samples: List[Dict[str, Any]]) -> Tuple[Set[str], Set[str], Set[str]]:
        urls, phones, upis = set(), set(), set()
        for s in samples:
            u_list = s.get("extracted_urls", []) or re.findall(r"https?://[^\s<>\"'()]+", s.get("content", ""))
            for u in u_list:
                try:
                    d = urlparse(u if "://" in u else "http://" + u).netloc.lower()
                    if d:
                        urls.add(d)
                except Exception:
                    pass
            for p in s.get("extracted_phones", []):
                clean_p = re.sub(r"\D", "", p)
                if len(clean_p) >= 10:
                    phones.add(clean_p[-10:])
            for u in s.get("extracted_upis", []):
                upis.add(u.strip().lower())
        return urls, phones, upis

    tr_urls, tr_phones, tr_upis = extract_entities(train_samples)
    te_urls, te_phones, te_upis = extract_entities(test_samples)

    url_overlap = tr_urls.intersection(te_urls)
    phone_overlap = tr_phones.intersection(te_phones)
    upi_overlap = tr_upis.intersection(te_upis)

    results["entity_leakage"] = {
        "train_unique_domains": len(tr_urls),
        "test_unique_domains": len(te_urls),
        "domain_overlap_count": len(url_overlap),
        "domain_overlap_examples": list(url_overlap)[:10],
        "train_unique_phones": len(tr_phones),
        "test_unique_phones": len(te_phones),
        "phone_overlap_count": len(phone_overlap),
        "phone_overlap_examples": list(phone_overlap)[:10],
        "train_unique_upis": len(tr_upis),
        "test_unique_upis": len(te_upis),
        "upi_overlap_count": len(upi_overlap),
        "upi_overlap_examples": list(upi_overlap)[:10],
    }

    # 4. Feature Cosine Similarity Leakage Audit
    tfidf = TfidfVectorizer(max_features=5000, ngram_range=(1, 2))
    all_texts = [s["content"] for s in train_samples] + [s["content"] for s in test_samples]
    tfidf.fit(all_texts)

    X_train = tfidf.transform([s["content"] for s in train_samples])
    X_test = tfidf.transform([s["content"] for s in test_samples])

    sim_matrix = cosine_similarity(X_test, X_train)
    max_sims = np.max(sim_matrix, axis=1)

    exact_feature_matches = int(np.sum(max_sims >= 0.999))
    near_dupes_95 = int(np.sum((max_sims >= 0.95) & (max_sims < 0.999)))
    near_dupes_90 = int(np.sum((max_sims >= 0.90) & (max_sims < 0.95)))
    near_dupes_80 = int(np.sum((max_sims >= 0.80) & (max_sims < 0.90)))

    results["cosine_similarity_audit"] = {
        "exact_feature_vectors_1_0": exact_feature_matches,
        "near_duplicates_ge_95": near_dupes_95,
        "near_duplicates_90_to_95": near_dupes_90,
        "near_duplicates_80_to_90": near_dupes_80,
        "total_test_samples": len(test_samples),
        "pct_test_samples_ge_90_similarity": round((exact_feature_matches + near_dupes_95 + near_dupes_90) / len(test_samples) * 100, 2),
        "pct_test_samples_ge_80_similarity": round((exact_feature_matches + near_dupes_95 + near_dupes_90 + near_dupes_80) / len(test_samples) * 100, 2),
        "mean_max_train_similarity": round(float(np.mean(max_sims)), 4),
        "median_max_train_similarity": round(float(np.median(max_sims)), 4),
    }

    # 5. Structural Template Leakage Audit
    train_templates = Counter(extract_template_signature(s["content"]) for s in train_samples)
    val_templates = Counter(extract_template_signature(s["content"]) for s in val_samples)
    test_templates = Counter(extract_template_signature(s["content"]) for s in test_samples)

    shared_templates_tr_te = set(train_templates.keys()).intersection(test_templates.keys())
    shared_templates_tr_va = set(train_templates.keys()).intersection(val_templates.keys())

    # Count how many test samples use a template from train
    test_samples_in_train_templates = sum(
        1 for s in test_samples if extract_template_signature(s["content"]) in train_templates
    )
    test_template_leakage_rate = (test_samples_in_train_templates / len(test_samples)) * 100

    results["structural_template_leakage"] = {
        "unique_templates_train": len(train_templates),
        "unique_templates_val": len(val_templates),
        "unique_templates_test": len(test_templates),
        "shared_templates_train_test": len(shared_templates_tr_te),
        "shared_templates_train_val": len(shared_templates_tr_va),
        "test_samples_with_template_in_train": test_samples_in_train_templates,
        "total_test_samples": len(test_samples),
        "test_template_leakage_rate_pct": round(test_template_leakage_rate, 2),
        "top_leaked_templates": [
            {
                "template": t,
                "train_occurrences": train_templates[t],
                "test_occurrences": test_templates[t],
            }
            for t in list(shared_templates_tr_te)[:8]
        ],
    }

    return results


if __name__ == "__main__":
    res = audit_leakage()
    print(json.dumps(res, indent=2))
