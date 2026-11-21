"""Model A: TF-IDF + Logistic Regression Baseline for Scam Detection."""

from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import FeatureUnion

from scamshield_ml.evaluation.metrics import compute_metrics
from scamshield_ml.models.base import BaseModel, PredictionOutput

logger = logging.getLogger(__name__)


class LogisticRegressionScamModel(BaseModel):
    """Word + Character N-Gram TF-IDF with Balanced Logistic Regression."""

    def __init__(self, c_param: float = 1.0, max_iter: int = 1000, threshold: float = 0.50) -> None:
        super().__init__(name="logistic_regression", threshold=threshold)
        self.c_param = c_param
        self.max_iter = max_iter

        # Combined word & char n-gram representation
        self.vectorizer = FeatureUnion([
            ("word_ngram", TfidfVectorizer(ngram_range=(1, 3), max_features=5000, sublinear_tf=True)),
            ("char_ngram", TfidfVectorizer(ngram_range=(2, 5), analyzer="char", max_features=10000, sublinear_tf=True)),
        ])
        self.classifier = LogisticRegression(
            C=self.c_param,
            max_iter=self.max_iter,
            class_weight="balanced",
            random_state=42,
        )

    def train(
        self,
        train_samples: List[Dict[str, Any]],
        val_samples: Optional[List[Dict[str, Any]]] = None,
        resume: bool = False,
        checkpoint_cb: Optional[Callable[[int, int, Dict[str, Any]], None]] = None,
    ) -> Dict[str, Any]:
        start_time = time.time()
        X_train_raw = [s["content"] for s in train_samples]
        y_train = [int(s["is_scam"]) for s in train_samples]

        logger.info("Extracting TF-IDF features for %d training samples...", len(X_train_raw))
        X_train = self.vectorizer.fit_transform(X_train_raw)

        logger.info("Fitting Logistic Regression (C=%s)...", self.c_param)
        self.classifier.fit(X_train, y_train)
        self.is_trained = True

        duration = time.time() - start_time
        metrics: Dict[str, Any] = {"training_duration_sec": round(duration, 3)}

        if val_samples:
            val_metrics = self.evaluate(val_samples)
            metrics.update(val_metrics)

        self.training_metrics = metrics
        if checkpoint_cb:
            checkpoint_cb(1, 1, metrics)

        return metrics

    def predict_one(self, content: str) -> PredictionOutput:
        start = time.time()
        X = self.vectorizer.transform([content])
        prob = float(self.classifier.predict_proba(X)[0][1])
        pred = int(prob >= self.threshold)
        latency = (time.time() - start) * 1000.0

        return PredictionOutput(
            is_scam=pred,
            scam_probability=round(prob, 4),
            label="SCAM" if pred == 1 else "LEGITIMATE",
            confidence=round(prob if pred == 1 else 1.0 - prob, 4),
            model_name=self.name,
            features_used=["word_tfidf", "char_tfidf"],
            latency_ms=round(latency, 2),
        )

    def predict_batch(self, contents: List[str]) -> List[PredictionOutput]:
        return [self.predict_one(c) for c in contents]

    def evaluate(self, test_samples: List[Dict[str, Any]]) -> Dict[str, Any]:
        start = time.time()
        X_test_raw = [s["content"] for s in test_samples]
        y_true = [int(s["is_scam"]) for s in test_samples]

        X_test = self.vectorizer.transform(X_test_raw)
        y_prob = [float(p[1]) for p in self.classifier.predict_proba(X_test)]
        y_pred = [int(p >= self.threshold) for p in y_prob]

        total_latency = (time.time() - start) * 1000.0
        avg_latency = total_latency / max(1, len(test_samples))

        metrics = compute_metrics(
            y_true=y_true,
            y_pred=y_pred,
            y_prob=y_prob,
            samples=test_samples,
            latency_ms=avg_latency,
        )
        self.evaluation_metrics = metrics
        return metrics

    def save(self, filepath: str) -> None:
        Path(filepath).parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(
            {
                "name": self.name,
                "c_param": self.c_param,
                "vectorizer": self.vectorizer,
                "classifier": self.classifier,
                "training_metrics": self.training_metrics,
                "evaluation_metrics": self.evaluation_metrics,
            },
            filepath,
        )

    def load(self, filepath: str) -> None:
        data = joblib.load(filepath)
        self.name = data["name"]
        self.c_param = data.get("c_param", 1.0)
        self.vectorizer = data["vectorizer"]
        self.classifier = data["classifier"]
        self.training_metrics = data.get("training_metrics", {})
        self.evaluation_metrics = data.get("evaluation_metrics", {})
        self.is_trained = True
