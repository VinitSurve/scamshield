"""Model B: K-Nearest Neighbors (KNN) with Latent Semantic Analysis."""

from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional
import joblib
from sklearn.decomposition import TruncatedSVD
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.neighbors import KNeighborsClassifier

from scamshield_ml.evaluation.metrics import compute_metrics
from scamshield_ml.models.base import BaseModel, PredictionOutput

logger = logging.getLogger(__name__)


class KNNScamModel(BaseModel):
    """K-Nearest Neighbors on dense TF-IDF SVD embeddings with Cosine Distance."""

    def __init__(self, n_neighbors: int = 5, n_components: int = 40) -> None:
        super().__init__(name="knn")
        self.n_neighbors = n_neighbors
        self.n_components = n_components

        self.vectorizer = TfidfVectorizer(ngram_range=(1, 2), max_features=4000, sublinear_tf=True)
        self.svd = TruncatedSVD(n_components=self.n_components, random_state=42)
        self.classifier = KNeighborsClassifier(n_neighbors=self.n_neighbors, metric="cosine")

    def train(
        self,
        train_samples: List[Dict[str, Any]],
        val_samples: Optional[List[Dict[str, Any]]] = None,
        resume: bool = False,
        checkpoint_cb: Optional[Callable[[int, int, Dict[str, Any]], None]] = None,
    ) -> Dict[str, Any]:
        start_time = time.time()
        X_raw = [s["content"] for s in train_samples]
        y_train = [int(s["is_scam"]) for s in train_samples]

        logger.info("Extracting TF-IDF and SVD representations for KNN...")
        X_tfidf = self.vectorizer.fit_transform(X_raw)
        # Ensure n_components does not exceed features or samples
        n_comp = min(self.n_components, X_tfidf.shape[1] - 1, len(X_raw) - 1)
        self.svd.set_params(n_components=max(2, n_comp))
        X_dense = self.svd.fit_transform(X_tfidf)

        logger.info("Fitting KNN with k=%d (cosine metric)...", self.n_neighbors)
        self.classifier.fit(X_dense, y_train)
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
        X_tfidf = self.vectorizer.transform([content])
        X_dense = self.svd.transform(X_tfidf)

        prob = float(self.classifier.predict_proba(X_dense)[0][1])
        pred = int(prob >= 0.5)
        latency = (time.time() - start) * 1000.0

        return PredictionOutput(
            is_scam=pred,
            scam_probability=round(prob, 4),
            label="SCAM" if pred == 1 else "LEGITIMATE",
            confidence=round(prob if pred == 1 else 1.0 - prob, 4),
            model_name=self.name,
            features_used=["tfidf_svd_cosine"],
            latency_ms=round(latency, 2),
        )

    def predict_batch(self, contents: List[str]) -> List[PredictionOutput]:
        return [self.predict_one(c) for c in contents]

    def evaluate(self, test_samples: List[Dict[str, Any]]) -> Dict[str, Any]:
        start = time.time()
        X_raw = [s["content"] for s in test_samples]
        y_true = [int(s["is_scam"]) for s in test_samples]

        X_tfidf = self.vectorizer.transform(X_raw)
        X_dense = self.svd.transform(X_tfidf)

        y_prob = [float(p[1]) for p in self.classifier.predict_proba(X_dense)]
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
                "n_neighbors": self.n_neighbors,
                "vectorizer": self.vectorizer,
                "svd": self.svd,
                "classifier": self.classifier,
                "training_metrics": self.training_metrics,
                "evaluation_metrics": self.evaluation_metrics,
            },
            filepath,
        )

    def load(self, filepath: str) -> None:
        data = joblib.load(filepath)
        self.name = data["name"]
        self.n_neighbors = data.get("n_neighbors", 5)
        self.vectorizer = data["vectorizer"]
        self.svd = data["svd"]
        self.classifier = data["classifier"]
        self.training_metrics = data.get("training_metrics", {})
        self.evaluation_metrics = data.get("evaluation_metrics", {})
        self.is_trained = True
