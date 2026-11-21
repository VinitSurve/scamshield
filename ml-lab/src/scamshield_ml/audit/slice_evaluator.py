"""Phase 7: Granular Slice-Based Model Evaluation & Sample Size Audit."""

from __future__ import annotations

import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List

import numpy as np
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score

from scamshield_ml.models.ensemble import EnsembleScamModel


def evaluate_slices() -> Dict[str, Any]:
    base_dir = Path(__file__).resolve().parent.parent.parent.parent
    data_dir = base_dir / "data" / "processed"
    models_dir = base_dir / "artifacts" / "models"

    with open(data_dir / "test.json", "r", encoding="utf-8") as f:
        test_samples = json.load(f)

    ensemble = EnsembleScamModel()
    ensemble.load(str(models_dir / "ensemble.joblib"))

    texts = [s["content"] for s in test_samples]
    y_true = np.array([1 if s["is_scam"] == 1 else 0 for s in test_samples])

    preds = ensemble.predict_batch(texts)
    y_pred = np.array([p.is_scam for p in preds])
    y_probs = np.array([p.scam_probability for p in preds])

    def compute_slice_metrics(indices: List[int], slice_name: str) -> Dict[str, Any]:
        count = len(indices)
        if count == 0:
            return {"count": 0, "status": "EMPTY_SLICE"}

        sub_true = y_true[indices]
        sub_pred = y_pred[indices]

        acc = accuracy_score(sub_true, sub_pred)
        prec = precision_score(sub_true, sub_pred, zero_division=0)
        rec = recall_score(sub_true, sub_pred, zero_division=0)
        f1 = f1_score(sub_true, sub_pred, zero_division=0)

        tp = sum(1 for t, p in zip(sub_true, sub_pred) if t == 1 and p == 1)
        fp = sum(1 for t, p in zip(sub_true, sub_pred) if t == 0 and p == 1)
        tn = sum(1 for t, p in zip(sub_true, sub_pred) if t == 0 and p == 0)
        fn = sum(1 for t, p in zip(sub_true, sub_pred) if t == 1 and p == 0)

        fpr = fp / (tn + fp) if (tn + fp) > 0 else 0.0

        reliability = "ROBUST_SAMPLE_SIZE"
        if count < 10:
            reliability = "CRITICALLY_SMALL_SAMPLE (UNRELIABLE METRIC)"
        elif count < 20:
            reliability = "LOW_SAMPLE_SIZE (INTERPRET WITH CAUTION)"

        return {
            "slice": slice_name,
            "sample_count": count,
            "sample_reliability": reliability,
            "accuracy_pct": round(acc * 100, 2),
            "precision_pct": round(prec * 100, 2),
            "recall_pct": round(rec * 100, 2),
            "f1_pct": round(f1 * 100, 2),
            "fpr_pct": round(fpr * 100, 2),
            "false_positive_count": int(fp),
            "false_negative_count": int(fn),
            "true_positive_count": int(tp),
            "true_negative_count": int(tn),
        }

    results: Dict[str, Any] = {
        "language_slices": {},
        "category_slices": {},
        "length_slices": {},
        "synthetic_slices": {},
        "url_presence_slices": {},
        "financial_slices": {},
        "banking_slices": {},
    }

    # 1. Language Slices
    lang_map = defaultdict(list)
    for i, s in enumerate(test_samples):
        lang_map[s.get("language", "unknown")].append(i)
    for lang, idxs in lang_map.items():
        results["language_slices"][lang] = compute_slice_metrics(idxs, f"Language: {lang}")

    # 2. Category Slices
    cat_map = defaultdict(list)
    for i, s in enumerate(test_samples):
        cat_map[s.get("category", "UNKNOWN")].append(i)
    for cat, idxs in cat_map.items():
        results["category_slices"][cat] = compute_slice_metrics(idxs, f"Category: {cat}")

    # 3. Length Slices
    short_idx, med_idx, long_idx = [], [], []
    for i, s in enumerate(test_samples):
        c_len = len(s["content"])
        if c_len < 60:
            short_idx.append(i)
        elif c_len <= 160:
            med_idx.append(i)
        else:
            long_idx.append(i)
    results["length_slices"]["short_lt_60"] = compute_slice_metrics(short_idx, "Short (< 60 chars)")
    results["length_slices"]["medium_60_160"] = compute_slice_metrics(med_idx, "Medium (60-160 chars)")
    results["length_slices"]["long_gt_160"] = compute_slice_metrics(long_idx, "Long (> 160 chars)")

    # 4. Synthetic Slices
    synth_idx = [i for i, s in enumerate(test_samples) if s.get("synthetic", True)]
    non_synth_idx = [i for i, s in enumerate(test_samples) if not s.get("synthetic", True)]
    results["synthetic_slices"]["synthetic"] = compute_slice_metrics(synth_idx, "Synthetic Samples")
    results["synthetic_slices"]["non_synthetic"] = compute_slice_metrics(non_synth_idx, "Non-Synthetic (Curated/Hard-Negatives)")

    # 5. URL Presence Slices
    has_url_idx, no_url_idx = [], []
    for i, s in enumerate(test_samples):
        has_url = bool(s.get("extracted_urls") or re.search(r"https?://|\b\w+\.(?:com|in|top|xyz|gd|ly)\b", s["content"]))
        if has_url:
            has_url_idx.append(i)
        else:
            no_url_idx.append(i)
    results["url_presence_slices"]["url_present"] = compute_slice_metrics(has_url_idx, "URL Present")
    results["url_presence_slices"]["url_absent"] = compute_slice_metrics(no_url_idx, "URL Absent")

    # 6. Financial Slices
    fin_terms = re.compile(r"₹|rs\b|inr|account|bank|upi|neft|rtgs|debit|credit|balance|refund|payment", re.I)
    fin_idx, non_fin_idx = [], []
    for i, s in enumerate(test_samples):
        if fin_terms.search(s["content"]):
            fin_idx.append(i)
        else:
            non_fin_idx.append(i)
    results["financial_slices"]["financial_content"] = compute_slice_metrics(fin_idx, "Financial Context")
    results["financial_slices"]["non_financial_content"] = compute_slice_metrics(non_fin_idx, "Non-Financial Context")

    # 7. Banking Slices
    banking_terms = re.compile(r"sbi|hdfc|icici|axis|pnb|kotak|canara|baroda|union bank|bank", re.I)
    bank_idx, non_bank_idx = [], []
    for i, s in enumerate(test_samples):
        if banking_terms.search(s["content"]):
            bank_idx.append(i)
        else:
            non_bank_idx.append(i)
    results["banking_slices"]["banking_brand_present"] = compute_slice_metrics(bank_idx, "Banking Brand Mentioned")
    results["banking_slices"]["no_banking_brand"] = compute_slice_metrics(non_bank_idx, "No Banking Brand")

    return results


if __name__ == "__main__":
    res = evaluate_slices()
    print(json.dumps(res, indent=2))
