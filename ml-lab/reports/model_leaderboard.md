# ScamShield ML Lab — Empirical Model Leaderboard

> **Evaluation Protocol:** Strictly evaluated on held-out test split (`test.json`) with zero data leakage.

| Rank | Model | Accuracy | Precision | Recall | Macro F1 | F1 Score | False Positive Rate | ROC-AUC | Latency (ms) |
|:---:|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **#1** | `ensemble` | 89.3% | 87.5% | 100.0% | 83.0% | **93.3%** | 42.9% | 0.980 | 1.1ms |
| **#2** | `url` | 85.7% | 84.0% | 100.0% | 75.6% | **91.3%** | 57.1% | 0.850 | 0.0ms |
| **#3** | `knn` | 85.7% | 84.0% | 100.0% | 75.6% | **91.3%** | 57.1% | 0.830 | 0.0ms |
| **#4** | `logistic` | 85.7% | 84.0% | 100.0% | 75.6% | **91.3%** | 57.1% | 0.959 | 0.1ms |
| **#5** | `ann` | 75.0% | 75.0% | 100.0% | 42.9% | **85.7%** | 100.0% | 0.980 | 0.0ms |
