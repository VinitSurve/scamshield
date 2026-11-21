"""Model E: Calibrated Soft-Voting Ensemble Learning Engine."""

from __future__ import annotations

import logging
import re
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional
import joblib

from scamshield_ml.evaluation.metrics import compute_metrics
from scamshield_ml.models.ann import ANNScamModel
from scamshield_ml.models.base import BaseModel, PredictionOutput
from scamshield_ml.models.knn import KNNScamModel
from scamshield_ml.models.logistic_regression import LogisticRegressionScamModel
from scamshield_ml.models.url_classifier import URLFeatureClassifier

logger = logging.getLogger(__name__)


class EnsembleScamModel(BaseModel):
    """Calibrated Multi-Model Soft Voting Ensemble."""

    def __init__(
        self,
        weights: Optional[Dict[str, float]] = None,
    ) -> None:
        super().__init__(name="ensemble")
        self.weights = weights or {
            "logistic_regression": 0.35,
            "ann": 0.35,
            "knn": 0.15,
            "url_classifier": 0.15,
        }
        self.logistic = LogisticRegressionScamModel()
        self.knn = KNNScamModel()
        self.ann = ANNScamModel()
        self.url_model = URLFeatureClassifier()

    def train(
        self,
        train_samples: List[Dict[str, Any]],
        val_samples: Optional[List[Dict[str, Any]]] = None,
        resume: bool = False,
        checkpoint_cb: Optional[Callable[[int, int, Dict[str, Any]], None]] = None,
    ) -> Dict[str, Any]:
        start_time = time.time()
        logger.info("Training constituent models for the Ensemble...")

        # 1. Train Logistic Regression
        logger.info("Ensemble [1/4]: Training Logistic Regression...")
        self.logistic.train(train_samples, val_samples, resume=resume)

        # 2. Train KNN
        logger.info("Ensemble [2/4]: Training KNN...")
        self.knn.train(train_samples, val_samples, resume=resume)

        # 3. Train ANN
        logger.info("Ensemble [3/4]: Training ANN...")
        self.ann.train(train_samples, val_samples, resume=resume)

        # 4. Train URL Model
        logger.info("Ensemble [4/4]: Training URL Classifier...")
        self.url_model.train(train_samples, val_samples, resume=resume)

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
        is_lone_url = content.strip().startswith(("http://", "https://", "www."))
        has_url = is_lone_url or bool(re.search(r"https?://[^\s<>\"'()]+|www\.[^\s<>\"'()]+", content))

        # Adjust weights dynamically based on input modality
        w = dict(self.weights)
        if is_lone_url:
            w["url_classifier"] = 0.50
            w["logistic_regression"] = 0.25
            w["knn"] = 0.15
            w["ann"] = 0.10
        elif has_url:
            w["url_classifier"] = 0.30
            w["logistic_regression"] = 0.40
            w["knn"] = 0.20
            w["ann"] = 0.10
        else:
            # If text contains no URL, URL classifier has zero signal and must not inject false prior bias
            w["url_classifier"] = 0.00
            w["logistic_regression"] = 0.55
            w["knn"] = 0.30
            w["ann"] = 0.15

        p_log = self.logistic.predict_one(content).scam_probability
        p_ann = self.ann.predict_one(content).scam_probability
        p_knn = self.knn.predict_one(content).scam_probability
        p_url = self.url_model.predict_one(content).scam_probability if has_url else 0.0

        weighted_prob = (
            w["logistic_regression"] * p_log +
            w["ann"] * p_ann +
            w["knn"] * p_knn +
            w["url_classifier"] * p_url
        )

        pred = int(weighted_prob >= 0.5)
        latency = (time.time() - start) * 1000.0

        return PredictionOutput(
            is_scam=pred,
            scam_probability=round(weighted_prob, 4),
            label="SCAM" if pred == 1 else "LEGITIMATE",
            confidence=round(weighted_prob if pred == 1 else 1.0 - weighted_prob, 4),
            model_name=self.name,
            features_used=[
                f"logistic({p_log:.2f})",
                f"ann({p_ann:.2f})",
                f"knn({p_knn:.2f})",
                f"url({p_url:.2f})",
            ],
            latency_ms=round(latency, 2),
        )

    def predict_batch(self, contents: List[str]) -> List[PredictionOutput]:
        return [self.predict_one(c) for c in contents]

    def evaluate(self, test_samples: List[Dict[str, Any]]) -> Dict[str, Any]:
        start = time.time()
        y_true = [int(s["is_scam"]) for s in test_samples]
        preds = [self.predict_one(s["content"]) for s in test_samples]
        y_prob = [p.scam_probability for p in preds]
        y_pred = [p.is_scam for p in preds]

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
                "weights": self.weights,
                "logistic": self.logistic,
                "knn": self.knn,
                "ann": self.ann,
                "url_model": self.url_model,
                "training_metrics": self.training_metrics,
                "evaluation_metrics": self.evaluation_metrics,
            },
            filepath,
        )

    def load(self, filepath: str) -> None:
        data = joblib.load(filepath)
        self.name = data["name"]
        self.weights = data.get("weights", self.weights)
        self.logistic = data["logistic"]
        self.knn = data["knn"]
        self.ann = data["ann"]
        self.url_model = data["url_model"]
        self.training_metrics = data.get("training_metrics", {})
        self.evaluation_metrics = data.get("evaluation_metrics", {})
        self.is_trained = True
