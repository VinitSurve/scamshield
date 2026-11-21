"""Comprehensive Cybersecurity Evaluation Metrics Engine."""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional
import numpy as np
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
    brier_score_loss,
)


def compute_metrics(
    y_true: List[int],
    y_pred: List[int],
    y_prob: Optional[List[float]] = None,
    samples: Optional[List[Dict[str, Any]]] = None,
    latency_ms: float = 0.0,
) -> Dict[str, Any]:
    """Computes comprehensive binary and subgroup cybersecurity metrics."""
    y_true_arr = np.array(y_true)
    y_pred_arr = np.array(y_pred)

    acc = float(accuracy_score(y_true_arr, y_pred_arr))
    prec = float(precision_score(y_true_arr, y_pred_arr, zero_division=0))
    rec = float(recall_score(y_true_arr, y_pred_arr, zero_division=0))
    f1 = float(f1_score(y_true_arr, y_pred_arr, zero_division=0))
    macro_f1 = float(f1_score(y_true_arr, y_pred_arr, average="macro", zero_division=0))

    cm = confusion_matrix(y_true_arr, y_pred_arr, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()

    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    fnr = float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0

    auc = 0.0
    brier = 0.0
    if y_prob is not None and len(set(y_true)) > 1:
        try:
            auc = float(roc_auc_score(y_true_arr, y_prob))
            brier = float(brier_score_loss(y_true_arr, y_prob))
        except Exception:
            pass

    metrics: Dict[str, Any] = {
        "accuracy": round(acc, 4),
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1": round(f1, 4),
        "macro_f1": round(macro_f1, 4),
        "fpr": round(fpr, 4),
        "fnr": round(fnr, 4),
        "roc_auc": round(auc, 4),
        "brier_score": round(brier, 4),
        "confusion_matrix": {
            "true_negatives": int(tn),
            "false_positives": int(fp),
            "false_negatives": int(fn),
            "true_positives": int(tp),
        },
        "latency_ms": round(latency_ms, 2),
        "total_samples": len(y_true),
    }

    # Language breakdown
    if samples and len(samples) == len(y_true):
        lang_breakdown: Dict[str, Dict[str, Any]] = {}
        languages = set(s.get("language", "unknown") for s in samples)
        for lang in languages:
            indices = [i for i, s in enumerate(samples) if s.get("language") == lang]
            if indices:
                sub_true = [y_true[i] for i in indices]
                sub_pred = [y_pred[i] for i in indices]
                sub_acc = float(accuracy_score(sub_true, sub_pred))
                sub_rec = float(recall_score(sub_true, sub_pred, zero_division=0))
                lang_breakdown[lang] = {
                    "count": len(indices),
                    "accuracy": round(sub_acc, 4),
                    "recall": round(sub_rec, 4),
                }
        metrics["language_breakdown"] = lang_breakdown

        # Category breakdown
        cat_breakdown: Dict[str, Dict[str, Any]] = {}
        categories = set(s.get("category", "unknown") for s in samples)
        for cat in categories:
            indices = [i for i, s in enumerate(samples) if s.get("category") == cat]
            if indices:
                sub_true = [y_true[i] for i in indices]
                sub_pred = [y_pred[i] for i in indices]
                sub_acc = float(accuracy_score(sub_true, sub_pred))
                sub_rec = float(recall_score(sub_true, sub_pred, zero_division=0))
                cat_breakdown[cat] = {
                    "count": len(indices),
                    "accuracy": round(sub_acc, 4),
                    "recall": round(sub_rec, 4),
                }
        metrics["category_breakdown"] = cat_breakdown

    return metrics
