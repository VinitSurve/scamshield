"""Model C: Artificial Neural Network (ANN / MLP) with Epoch Checkpointing & Resume."""

from __future__ import annotations

import copy
import logging
import time
import warnings
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional
import joblib
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.neural_network import MLPClassifier

from scamshield_ml.evaluation.metrics import compute_metrics
from scamshield_ml.models.base import BaseModel, PredictionOutput

logger = logging.getLogger(__name__)


class ANNScamModel(BaseModel):
    """Multi-Layer Perceptron Neural Network with epoch checkpointing and early stopping."""

    def __init__(
        self,
        hidden_layer_sizes: tuple = (64, 32),
        max_epochs: int = 25,
        learning_rate: float = 0.001,
        early_stopping_patience: int = 5,
    ) -> None:
        super().__init__(name="ann")
        self.hidden_layer_sizes = hidden_layer_sizes
        self.max_epochs = max_epochs
        self.learning_rate = learning_rate
        self.early_stopping_patience = early_stopping_patience

        self.vectorizer = TfidfVectorizer(ngram_range=(1, 3), max_features=5000, sublinear_tf=True)
        self.classifier = MLPClassifier(
            hidden_layer_sizes=self.hidden_layer_sizes,
            activation="relu",
            solver="adam",
            learning_rate_init=self.learning_rate,
            alpha=0.001,
            warm_start=True,  # Enables epoch-by-epoch resumption
            max_iter=1,
            random_state=42,
        )
        self.current_epoch = 0
        self.history: List[Dict[str, Any]] = []

    def train(
        self,
        train_samples: List[Dict[str, Any]],
        val_samples: Optional[List[Dict[str, Any]]] = None,
        resume: bool = False,
        checkpoint_cb: Optional[Callable[[int, int, Dict[str, Any]], None]] = None,
    ) -> Dict[str, Any]:
        start_time = time.time()
        X_train_raw = [s["content"] for s in train_samples]
        y_train = np.array([int(s["is_scam"]) for s in train_samples])

        if not resume or not self.is_trained:
            logger.info("Initializing vectorizer and network for ANN training...")
            X_train = self.vectorizer.fit_transform(X_train_raw)
            self.current_epoch = 0
            self.history = []
        else:
            logger.info("Resuming ANN from epoch %d / %d...", self.current_epoch, self.max_epochs)
            X_train = self.vectorizer.transform(X_train_raw)

        classes = np.array([0, 1])
        best_val_f1 = 0.0
        best_classifier = None
        patience_counter = 0

        for epoch in range(self.current_epoch + 1, self.max_epochs + 1):
            self.classifier.set_params(max_iter=epoch)
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                self.classifier.fit(X_train, y_train)
            self.current_epoch = epoch

            # Evaluate training loss
            train_loss = float(self.classifier.loss_)
            metrics_epoch: Dict[str, Any] = {
                "epoch": epoch,
                "loss": round(train_loss, 4),
            }

            if val_samples:
                val_eval = self.evaluate(val_samples)
                val_f1 = val_eval["f1"]
                metrics_epoch["val_f1"] = val_f1
                metrics_epoch["val_accuracy"] = val_eval["accuracy"]

                if val_f1 > best_val_f1:
                    best_val_f1 = val_f1
                    best_classifier = copy.deepcopy(self.classifier)
                    patience_counter = 0
                else:
                    patience_counter += 1

            self.history.append(metrics_epoch)

            # Invoke checkpoint callback
            if checkpoint_cb:
                checkpoint_cb(epoch, self.max_epochs, metrics_epoch)

            # Early stopping check
            if patience_counter >= self.early_stopping_patience:
                logger.info("Early stopping triggered at epoch %d (patience=%d)", epoch, self.early_stopping_patience)
                break

        if best_classifier is not None:
            self.classifier = best_classifier

        self.is_trained = True
        duration = time.time() - start_time
        metrics: Dict[str, Any] = {
            "training_duration_sec": round(duration, 3),
            "final_epoch": self.current_epoch,
            "final_loss": round(float(self.classifier.loss_), 4),
        }

        if val_samples:
            metrics.update(self.evaluate(val_samples))

        self.training_metrics = metrics
        return metrics

    def predict_one(self, content: str) -> PredictionOutput:
        start = time.time()
        X = self.vectorizer.transform([content])
        prob = float(self.classifier.predict_proba(X)[0][1])
        pred = int(prob >= 0.5)
        latency = (time.time() - start) * 1000.0

        return PredictionOutput(
            is_scam=pred,
            scam_probability=round(prob, 4),
            label="SCAM" if pred == 1 else "LEGITIMATE",
            confidence=round(prob if pred == 1 else 1.0 - prob, 4),
            model_name=self.name,
            features_used=["ann_mlp_dense_128_64"],
            latency_ms=round(latency, 2),
        )

    def predict_batch(self, contents: List[str]) -> List[PredictionOutput]:
        return [self.predict_one(c) for c in contents]

    def evaluate(self, test_samples: List[Dict[str, Any]]) -> Dict[str, Any]:
        start = time.time()
        X_raw = [s["content"] for s in test_samples]
        y_true = [int(s["is_scam"]) for s in test_samples]

        X_test = self.vectorizer.transform(X_raw)
        y_prob = [float(p[1]) for p in self.classifier.predict_proba(X_test)]
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
                "hidden_layer_sizes": self.hidden_layer_sizes,
                "current_epoch": self.current_epoch,
                "history": self.history,
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
        self.hidden_layer_sizes = data.get("hidden_layer_sizes", (128, 64))
        self.current_epoch = data.get("current_epoch", 0)
        self.history = data.get("history", [])
        self.vectorizer = data["vectorizer"]
        self.classifier = data["classifier"]
        self.training_metrics = data.get("training_metrics", {})
        self.evaluation_metrics = data.get("evaluation_metrics", {})
        self.is_trained = True
