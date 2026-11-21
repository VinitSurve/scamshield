"""Phase 1: Verification of Dataset v3 Claims & Model Metric Recalculation."""

from __future__ import annotations

import hashlib
import json
import time
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List

import joblib
import numpy as np
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    brier_score_loss,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)


def verify_claims() -> Dict[str, Any]:
    base_dir = Path(__file__).resolve().parent.parent.parent.parent
    data_dir = base_dir / "data" / "processed"
    manifest_path = base_dir / "datasets" / "dataset_manifest.json"
    models_dir = base_dir / "artifacts" / "models"

    results: Dict[str, Any] = {
        "dataset_files": {},
        "manifest_comparison": {},
        "recalculated_metrics": {},
        "discrepancies": [],
    }

    # 1. Inspect Files
    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    with open(data_dir / "clean_dataset.json", "r", encoding="utf-8") as f:
        clean_data = json.load(f)

    with open(data_dir / "train.json", "r", encoding="utf-8") as f:
        train_data = json.load(f)

    with open(data_dir / "val.json", "r", encoding="utf-8") as f:
        val_data = json.load(f)

    with open(data_dir / "test.json", "r", encoding="utf-8") as f:
        test_data = json.load(f)

    total_clean = len(clean_data)
    total_train = len(train_data)
    total_val = len(val_data)
    total_test = len(test_data)
    sum_splits = total_train + total_val + total_test

    # Compute content hash matching validator.py logic
    clean_hashes = [hashlib.sha256(str(s.get("content", "")).strip().encode()).hexdigest() for s in clean_data]
    computed_hash = hashlib.sha256(json.dumps(clean_hashes, sort_keys=True).encode()).hexdigest()[:12]

    # Content uniqueness
    raw_contents = [s.get("content", "") for s in clean_data]
    norm_contents = [" ".join(c.split()).lower() for c in raw_contents]
    unique_raw = len(set(raw_contents))
    unique_norm = len(set(norm_contents))

    # Class & Language & Category
    class_dist = dict(Counter("scam" if s.get("is_scam") == 1 else "legitimate" for s in clean_data))
    lang_dist = dict(Counter(s.get("language", "unknown") for s in clean_data))
    cat_dist = dict(Counter(s.get("category", "unknown") for s in clean_data))

    indic_langs = ["hi", "mr", "hinglish", "romanized_mr"]
    indic_count = sum(lang_dist.get(l, 0) for l in indic_langs)
    indic_pct = (indic_count / total_clean) * 100 if total_clean else 0

    results["dataset_files"] = {
        "clean_count": total_clean,
        "train_count": total_train,
        "val_count": total_val,
        "test_count": total_test,
        "sum_splits": sum_splits,
        "sum_matches_clean": sum_splits == total_clean,
        "unique_raw_content": unique_raw,
        "unique_normalized_content": unique_norm,
        "computed_dataset_hash": computed_hash,
        "manifest_hash": manifest.get("dataset_hash"),
        "hash_matches": computed_hash == manifest.get("dataset_hash"),
        "class_distribution": class_dist,
        "language_distribution": lang_dist,
        "indic_sample_count": indic_count,
        "indic_percentage": round(indic_pct, 2),
        "category_count": len(cat_dist),
    }

    # Verify against manifest claims
    for key, val in [
        ("total_samples", total_clean),
        ("splits.train_count", total_train),
        ("splits.val_count", total_val),
        ("splits.test_count", total_test),
    ]:
        m_val = manifest.get("total_samples") if "." not in key else manifest.get("splits", {}).get(key.split(".")[1])
        if m_val != val:
            results["discrepancies"].append(f"Manifest mismatch on {key}: expected {m_val}, actual {val}")

    # 2. Recalculate Metrics for Each Model
    from scamshield_ml.models.ann import ANNScamModel
    from scamshield_ml.models.ensemble import EnsembleScamModel
    from scamshield_ml.models.knn import KNNScamModel
    from scamshield_ml.models.logistic_regression import LogisticRegressionScamModel
    from scamshield_ml.models.url_classifier import URLFeatureClassifier

    y_test_true = np.array([1 if s.get("is_scam") == 1 else 0 for s in test_data])
    test_texts = [s.get("content", "") for s in test_data]

    model_constructors = {
        "ensemble": (EnsembleScamModel, "ensemble.joblib"),
        "logistic": (LogisticRegressionScamModel, "logistic.joblib"),
        "ann": (ANNScamModel, "ann.joblib"),
        "knn": (KNNScamModel, "knn.joblib"),
        "url": (URLFeatureClassifier, "url.joblib"),
    }

    for model_name, (cls, fname) in model_constructors.items():
        m_path = models_dir / fname
        if not m_path.exists():
            results["discrepancies"].append(f"Model file missing: {fname}")
            continue

        model = cls()
        model.load(str(m_path))

        try:
            preds = model.predict_batch(test_texts)
            y_probs = np.array([p.scam_probability for p in preds])
            y_preds = np.array([p.is_scam for p in preds])

            # Confusion Matrix
            cm = confusion_matrix(y_test_true, y_preds)
            tn, fp, fn, tp = cm.ravel()

            acc = accuracy_score(y_test_true, y_preds)
            prec = precision_score(y_test_true, y_preds, zero_division=0)
            rec = recall_score(y_test_true, y_preds, zero_division=0)
            f1 = f1_score(y_test_true, y_preds, zero_division=0)
            f1_scam = f1_score(y_test_true, y_preds, pos_label=1, zero_division=0)
            f1_legit = f1_score(y_test_true, y_preds, pos_label=0, zero_division=0)
            macro_f1 = (f1_scam + f1_legit) / 2.0
            specificity = tn / (tn + fp) if (tn + fp) > 0 else 0.0
            fpr = fp / (tn + fp) if (tn + fp) > 0 else 0.0
            fnr = fn / (tp + fn) if (tp + fn) > 0 else 0.0

            try:
                roc_auc = roc_auc_score(y_test_true, y_probs)
            except Exception:
                roc_auc = 0.5

            try:
                pr_auc = average_precision_score(y_test_true, y_probs)
            except Exception:
                pr_auc = 0.0

            brier = brier_score_loss(y_test_true, y_probs)

            # Single-item Latency benchmark: 5 warmup runs, then measure 292 single-sample inferences
            for _ in range(5):
                _ = model.predict_one(test_texts[0])

            latencies = []
            for text in test_texts:
                t0 = time.perf_counter()
                _ = model.predict_one(text)
                latencies.append((time.perf_counter() - t0) * 1000)

            mean_lat = np.mean(latencies)
            p50_lat = np.percentile(latencies, 50)
            p95_lat = np.percentile(latencies, 95)
            p99_lat = np.percentile(latencies, 99)

            results["recalculated_metrics"][model_name] = {
                "accuracy": round(acc, 4),
                "precision": round(prec, 4),
                "recall": round(rec, 4),
                "specificity": round(specificity, 4),
                "f1_score": round(f1, 4),
                "macro_f1": round(macro_f1, 4),
                "fpr": round(fpr, 4),
                "fnr": round(fnr, 4),
                "roc_auc": round(roc_auc, 4),
                "pr_auc": round(pr_auc, 4),
                "brier_score": round(brier, 4),
                "confusion_matrix": {
                    "tn": int(tn),
                    "fp": int(fp),
                    "fn": int(fn),
                    "tp": int(tp),
                },
                "latency_ms": {
                    "mean": round(mean_lat, 2),
                    "median": round(p50_lat, 2),
                    "p95": round(p95_lat, 2),
                    "p99": round(p99_lat, 2),
                },
                "threshold_used": model.threshold,
            }
        except Exception as e:
            results["discrepancies"].append(f"Failed to evaluate {model_name}: {e}")

    return results


if __name__ == "__main__":
    res = verify_claims()
    print(json.dumps(res, indent=2))
