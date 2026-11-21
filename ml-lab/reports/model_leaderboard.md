# ScamShield ML Lab — Empirical Model Leaderboard (v2.0.0-ca6930eccd7f)

> **Evaluation Protocol:** Best validated checkpoint per model on current held-out test split with zero data leakage.

| Rank | Model | Accuracy | Precision | Recall | Macro F1 | F1 Score | False Positive Rate | ROC-AUC | Latency (ms) |
|:---:|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **#1** | `ensemble` | 88.3% | 87.2% | 94.4% | 87.6% | **90.7%** | 20.8% | 0.915 | 1.1ms |
| **#2** | `logistic` | 88.3% | 87.2% | 94.4% | 87.6% | **90.7%** | 20.8% | 0.931 | 0.1ms |
| **#3** | `ann` | 86.7% | 93.8% | 83.3% | 86.4% | **88.2%** | 8.3% | 0.931 | 0.0ms |
| **#4** | `knn` | 75.0% | 80.0% | 77.8% | 74.1% | **78.9%** | 29.2% | 0.858 | 0.0ms |
| **#5** | `url` | 70.0% | 95.0% | 52.8% | 69.9% | **67.9%** | 4.2% | 0.782 | 0.0ms |
