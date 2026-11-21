# ScamShield ML Lab — Empirical Model Leaderboard (v3.0.0-f69bd734516c)

> **Evaluation Protocol:** Best validated checkpoint per model on current held-out test split with zero data leakage.

| Rank | Model | Accuracy | Precision | Recall | Macro F1 | F1 Score | False Positive Rate | ROC-AUC | Latency (ms) |
|:---:|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **#1** | `ensemble` | 97.6% | 97.6% | 98.2% | 97.6% | **97.9%** | 3.1% | 0.999 | 1.2ms |
| **#2** | `ann` | 97.6% | 97.6% | 98.2% | 97.6% | **97.9%** | 3.1% | 0.997 | 0.0ms |
| **#3** | `knn` | 97.3% | 97.0% | 98.2% | 97.2% | **97.6%** | 3.9% | 0.989 | 0.0ms |
| **#4** | `logistic` | 97.3% | 97.0% | 98.2% | 97.2% | **97.6%** | 3.9% | 0.998 | 0.1ms |
| **#5** | `url` | 80.8% | 100.0% | 66.1% | 80.8% | **79.6%** | 0.0% | 0.857 | 0.0ms |
