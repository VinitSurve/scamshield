"""Phase 3: Synthetic Data Bias Auditor & Group-Aware (Template-Disjoint) Evaluation."""

from __future__ import annotations

import json
import math
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, List, Tuple

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score
from sklearn.model_selection import GroupKFold

from scamshield_ml.audit.leakage_auditor import extract_template_signature


def compute_ttr(texts: List[str]) -> float:
    """Computes Type-Token Ratio (lexical diversity)."""
    tokens = []
    for t in texts:
        tokens.extend(re.findall(r"\w+", t.lower()))
    if not tokens:
        return 0.0
    return len(set(tokens)) / len(tokens)


def audit_synthetic_bias() -> Dict[str, Any]:
    base_dir = Path(__file__).resolve().parent.parent.parent.parent
    data_dir = base_dir / "data" / "processed"

    with open(data_dir / "clean_dataset.json", "r", encoding="utf-8") as f:
        clean_samples = json.load(f)

    results: Dict[str, Any] = {
        "synthetic_distribution": {},
        "template_statistics": {},
        "formulaic_comparison": {},
        "predictive_tokens": {},
        "group_aware_evaluation": {},
    }

    # 1. Synthetic Distribution
    total_samples = len(clean_samples)
    synthetic_samples = [s for s in clean_samples if s.get("synthetic", True)]
    non_synthetic_samples = [s for s in clean_samples if not s.get("synthetic", True)]

    synthetic_scam = sum(1 for s in synthetic_samples if s.get("is_scam") == 1)
    synthetic_legit = sum(1 for s in synthetic_samples if s.get("is_scam") == 0)

    results["synthetic_distribution"] = {
        "total_samples": total_samples,
        "synthetic_count": len(synthetic_samples),
        "synthetic_percentage": round(len(synthetic_samples) / total_samples * 100, 2),
        "non_synthetic_count": len(non_synthetic_samples),
        "non_synthetic_percentage": round(len(non_synthetic_samples) / total_samples * 100, 2),
        "synthetic_scam_count": synthetic_scam,
        "synthetic_legit_count": synthetic_legit,
    }

    # 2. Template Statistics
    template_map: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for s in clean_samples:
        sig = extract_template_signature(s["content"])
        template_map[sig].append(s)

    unique_templates = len(template_map)
    samples_per_template = [len(samples) for samples in template_map.values()]

    top_templates = sorted(template_map.items(), key=lambda x: len(x[1]), reverse=True)[:10]

    results["template_statistics"] = {
        "total_unique_templates": unique_templates,
        "mean_samples_per_template": round(float(np.mean(samples_per_template)), 2),
        "median_samples_per_template": round(float(np.median(samples_per_template)), 2),
        "max_samples_in_single_template": int(np.max(samples_per_template)),
        "templates_with_gt_5_samples": sum(1 for s in samples_per_template if s > 5),
        "templates_with_1_sample": sum(1 for s in samples_per_template if s == 1),
        "top_10_templates": [
            {
                "signature": sig[:100] + ("..." if len(sig) > 100 else ""),
                "sample_count": len(smps),
                "label": "scam" if smps[0].get("is_scam") == 1 else "legitimate",
                "category": smps[0].get("category"),
            }
            for sig, smps in top_templates
        ],
    }

    # 3. Formulaic Comparison (Scam vs Legitimate)
    scam_texts = [s["content"] for s in clean_samples if s.get("is_scam") == 1]
    legit_texts = [s["content"] for s in clean_samples if s.get("is_scam") == 0]

    scam_char_lens = [len(t) for t in scam_texts]
    legit_char_lens = [len(t) for t in legit_texts]

    scam_word_counts = [len(t.split()) for t in scam_texts]
    legit_word_counts = [len(t.split()) for t in legit_texts]

    scam_exclamations = [t.count("!") for t in scam_texts]
    legit_exclamations = [t.count("!") for t in legit_texts]

    results["formulaic_comparison"] = {
        "scam": {
            "mean_char_length": round(float(np.mean(scam_char_lens)), 1),
            "std_char_length": round(float(np.std(scam_char_lens)), 1),
            "mean_word_count": round(float(np.mean(scam_word_counts)), 1),
            "std_word_count": round(float(np.std(scam_word_counts)), 1),
            "type_token_ratio": round(compute_ttr(scam_texts), 4),
            "mean_exclamations": round(float(np.mean(scam_exclamations)), 2),
        },
        "legitimate": {
            "mean_char_length": round(float(np.mean(legit_char_lens)), 1),
            "std_char_length": round(float(np.std(legit_char_lens)), 1),
            "mean_word_count": round(float(np.mean(legit_word_counts)), 1),
            "std_word_count": round(float(np.std(legit_word_counts)), 1),
            "type_token_ratio": round(compute_ttr(legit_texts), 4),
            "mean_exclamations": round(float(np.mean(legit_exclamations)), 2),
        },
    }

    # 4. Token Exclusivity (Shortcut Words)
    scam_tokens = Counter()
    legit_tokens = Counter()
    for t in scam_texts:
        scam_tokens.update(set(re.findall(r"\b[a-zA-Z]{3,}\b", t.lower())))
    for t in legit_texts:
        legit_tokens.update(set(re.findall(r"\b[a-zA-Z]{3,}\b", t.lower())))

    all_vocab = set(scam_tokens.keys()).union(set(legit_tokens.keys()))
    predictive = []
    for word in all_vocab:
        sc = scam_tokens[word]
        lc = legit_tokens[word]
        total = sc + lc
        if total >= 25:
            scam_ratio = sc / total
            if scam_ratio >= 0.95 or scam_ratio <= 0.05:
                predictive.append({
                    "word": word,
                    "scam_occurrences": sc,
                    "legit_occurrences": lc,
                    "scam_ratio": round(scam_ratio, 3),
                    "dominant_class": "SCAM" if scam_ratio > 0.5 else "LEGITIMATE",
                })

    results["predictive_tokens"] = sorted(predictive, key=lambda x: abs(x["scam_ratio"] - 0.5), reverse=True)[:15]

    # 5. Group-Aware (Template-Disjoint) Evaluation
    # Using GroupKFold where group = template_signature
    all_texts = [s["content"] for s in clean_samples]
    all_labels = np.array([1 if s.get("is_scam") == 1 else 0 for s in clean_samples])
    all_groups = [extract_template_signature(s["content"]) for s in clean_samples]

    # Map groups to integer IDs
    group_to_id = {g: i for i, g in enumerate(set(all_groups))}
    group_ids = np.array([group_to_id[g] for g in all_groups])

    gkf = GroupKFold(n_splits=5)
    fold_accuracies = []
    fold_f1s = []
    fold_recalls = []
    fold_precisions = []
    fold_fprs = []

    for fold, (train_idx, test_idx) in enumerate(gkf.split(all_texts, all_labels, groups=group_ids)):
        X_tr = [all_texts[i] for i in train_idx]
        y_tr = all_labels[train_idx]
        X_te = [all_texts[i] for i in test_idx]
        y_te = all_labels[test_idx]

        # Train TF-IDF + Logistic Regression
        vec = TfidfVectorizer(max_features=5000, ngram_range=(1, 2))
        X_tr_tfidf = vec.fit_transform(X_tr)
        X_te_tfidf = vec.transform(X_te)

        clf = LogisticRegression(C=1.0, max_iter=1000, random_state=42)
        clf.fit(X_tr_tfidf, y_tr)

        y_pred = clf.predict(X_te_tfidf)

        acc = accuracy_score(y_te, y_pred)
        f1 = f1_score(y_te, y_pred, zero_division=0)
        rec = recall_score(y_te, y_pred, zero_division=0)
        prec = precision_score(y_te, y_pred, zero_division=0)

        # FPR
        tn = sum(1 for yt, yp in zip(y_te, y_pred) if yt == 0 and yp == 0)
        fp = sum(1 for yt, yp in zip(y_te, y_pred) if yt == 0 and yp == 1)
        fpr = fp / (tn + fp) if (tn + fp) > 0 else 0.0

        fold_accuracies.append(acc)
        fold_f1s.append(f1)
        fold_recalls.append(rec)
        fold_precisions.append(prec)
        fold_fprs.append(fpr)

    results["group_aware_evaluation"] = {
        "evaluation_strategy": "5-Fold GroupKFold strictly grouped by template signature (zero template leakage)",
        "mean_out_of_template_accuracy": round(float(np.mean(fold_accuracies)) * 100, 2),
        "mean_out_of_template_f1": round(float(np.mean(fold_f1s)) * 100, 2),
        "mean_out_of_template_recall": round(float(np.mean(fold_recalls)) * 100, 2),
        "mean_out_of_template_precision": round(float(np.mean(fold_precisions)) * 100, 2),
        "mean_out_of_template_fpr": round(float(np.mean(fold_fprs)) * 100, 2),
        "fold_f1_scores": [round(f * 100, 2) for f in fold_f1s],
        "drop_from_reported_f1": round(97.9 - float(np.mean(fold_f1s)) * 100, 2),
    }

    return results


if __name__ == "__main__":
    res = audit_synthetic_bias()
    print(json.dumps(res, indent=2))
