"""Model D: Dedicated URL Structural & Lexical Feature Classifier."""

from __future__ import annotations

import logging
import re
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional
import joblib
import numpy as np
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.preprocessing import StandardScaler

from scamshield_ml.evaluation.metrics import compute_metrics
from scamshield_ml.features.url_features import URLFeatureExtractor
from scamshield_ml.models.base import BaseModel, PredictionOutput

logger = logging.getLogger(__name__)


class URLFeatureClassifier(BaseModel):
    """Dedicated URL security classifier evaluating structural, lexical, and impersonation features."""

    def __init__(self, n_estimators: int = 100, max_depth: int = 4) -> None:
        super().__init__(name="url_classifier")
        self.n_estimators = n_estimators
        self.max_depth = max_depth

        self.scaler = StandardScaler()
        self.classifier = GradientBoostingClassifier(
            n_estimators=self.n_estimators,
            max_depth=self.max_depth,
            random_state=42,
        )

    def _extract_matrix(self, samples: List[Dict[str, Any]]) -> np.ndarray:
        vectors = []
        for s in samples:
            # If sample has extracted URLs, inspect the first URL; otherwise treat content as URL
            content = s.get("content", "")
            urls = s.get("extracted_urls", [])
            target = urls[0] if urls else content
            feats = URLFeatureExtractor.extract_features(target)
            vectors.append(URLFeatureExtractor.to_vector(feats))
        return np.array(vectors)

    def train(
        self,
        train_samples: List[Dict[str, Any]],
        val_samples: Optional[List[Dict[str, Any]]] = None,
        resume: bool = False,
        checkpoint_cb: Optional[Callable[[int, int, Dict[str, Any]], None]] = None,
    ) -> Dict[str, Any]:
        start_time = time.time()
        logger.info("Extracting 20 structural features for %d URL/message samples...", len(train_samples))
        X_raw = self._extract_matrix(train_samples)
        y_train = np.array([int(s["is_scam"]) for s in train_samples])

        X_scaled = self.scaler.fit_transform(X_raw)

        logger.info("Training Gradient Boosting URL Classifier (%d estimators)...", self.n_estimators)
        self.classifier.fit(X_scaled, y_train)
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
        # Verify if content contains any URL candidate
        has_url = content.strip().startswith(("http://", "https://", "www.")) or bool(
            re.search(r"https?://[^\s<>\"'()]+|\b[a-zA-Z0-9-]{2,63}\.(?:top|xyz|in|com|org|net|gov|edu|co)\b", content)
        )
        if not has_url:
            return PredictionOutput(
                is_scam=0,
                scam_probability=0.0,
                label="LEGITIMATE",
                confidence=1.0,
                model_name=self.name,
                features_used=["no_url_candidate"],
                latency_ms=0.05,
            )

        feats = URLFeatureExtractor.extract_features(content)
        vec = np.array([URLFeatureExtractor.to_vector(feats)])
        vec_scaled = self.scaler.transform(vec)

        prob = float(self.classifier.predict_proba(vec_scaled)[0][1])
        pred = int(prob >= 0.5)
        latency = (time.time() - start) * 1000.0

        return PredictionOutput(
            is_scam=pred,
            scam_probability=round(prob, 4),
            label="SCAM" if pred == 1 else "LEGITIMATE",
            confidence=round(prob if pred == 1 else 1.0 - prob, 4),
            model_name=self.name,
            features_used=URLFeatureExtractor.FEATURE_NAMES,
            latency_ms=round(latency, 2),
        )

    def predict_batch(self, contents: List[str]) -> List[PredictionOutput]:
        return [self.predict_one(c) for c in contents]

    def evaluate(self, test_samples: List[Dict[str, Any]]) -> Dict[str, Any]:
        start = time.time()
        X_raw = self._extract_matrix(test_samples)
        y_true = [int(s["is_scam"]) for s in test_samples]

        X_scaled = self.scaler.transform(X_raw)
        y_prob = [float(p[1]) for p in self.classifier.predict_proba(X_scaled)]
        y_pred = [int(p >= 0.5) for p in y_prob]

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
                "n_estimators": self.n_estimators,
                "max_depth": self.max_depth,
                "scaler": self.scaler,
                "classifier": self.classifier,
                "training_metrics": self.training_metrics,
                "evaluation_metrics": self.evaluation_metrics,
            },
            filepath,
        )

    def load(self, filepath: str) -> None:
        data = joblib.load(filepath)
        self.name = data["name"]
        self.n_estimators = data.get("n_estimators", 100)
        self.max_depth = data.get("max_depth", 4)
        self.scaler = data["scaler"]
        self.classifier = data["classifier"]
        self.training_metrics = data.get("training_metrics", {})
        self.evaluation_metrics = data.get("evaluation_metrics", {})
        self.is_trained = True
