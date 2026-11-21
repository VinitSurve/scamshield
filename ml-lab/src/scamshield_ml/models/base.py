"""Abstract Base Class for ScamShield Machine Learning Models."""

from __future__ import annotations

import abc
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Tuple


@dataclass
class PredictionOutput:
    is_scam: int  # 0 or 1
    scam_probability: float  # 0.0 to 1.0
    label: str  # "SCAM" or "LEGITIMATE"
    confidence: float
    model_name: str
    features_used: List[str]
    latency_ms: float


class BaseModel(abc.ABC):
    """Abstract model contract for training, evaluation, checkpointing, and prediction."""

    def __init__(self, name: str) -> None:
        self.name = name
        self.is_trained = False
        self.training_metrics: Dict[str, Any] = {}
        self.evaluation_metrics: Dict[str, Any] = {}

    @abc.abstractmethod
    def train(
        self,
        train_samples: List[Dict[str, Any]],
        val_samples: Optional[List[Dict[str, Any]]] = None,
        resume: bool = False,
        checkpoint_cb: Optional[Callable[[int, int, Dict[str, Any]], None]] = None,
    ) -> Dict[str, Any]:
        """Trains the model and returns validation metrics."""
        raise NotImplementedError

    @abc.abstractmethod
    def predict_one(self, content: str) -> PredictionOutput:
        """Runs single-sample inference."""
        raise NotImplementedError

    @abc.abstractmethod
    def predict_batch(self, contents: List[str]) -> List[PredictionOutput]:
        """Runs batch inference."""
        raise NotImplementedError

    @abc.abstractmethod
    def evaluate(self, test_samples: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Evaluates on held-out test data and computes full metrics suite."""
        raise NotImplementedError

    @abc.abstractmethod
    def save(self, filepath: str) -> None:
        """Serializes model artifacts to disk."""
        raise NotImplementedError

    @abc.abstractmethod
    def load(self, filepath: str) -> None:
        """Loads model artifacts from disk."""
        raise NotImplementedError
