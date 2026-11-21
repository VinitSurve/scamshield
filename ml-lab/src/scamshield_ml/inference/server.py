"""ScamShield Fast Inference API Server for Platform Integration."""

from __future__ import annotations

import logging
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel as PydanticBaseModel, Field

from scamshield_ml.models.ensemble import EnsembleScamModel
from scamshield_ml.orchestration.orchestrator import MainOrchestrator
from scamshield_ml.orchestration.provider_keys import ProviderKeyManager
from scamshield_ml.state import ARTIFACTS_DIR, StateManager

logger = logging.getLogger(__name__)

app = FastAPI(
    title="ScamShield ML Intelligence & Multi-Agent Inference API",
    version="1.0.0",
    description="Unified cybersecurity inference API serving ML models and multi-agent threat intelligence.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global orchestrator instance
_orchestrator: Optional[MainOrchestrator] = None


def get_orchestrator() -> MainOrchestrator:
    global _orchestrator
    if _orchestrator is None:
        ensemble_path = ARTIFACTS_DIR / "models" / "ensemble.joblib"
        ensemble = None
        if ensemble_path.exists():
            try:
                ensemble = EnsembleScamModel()
                ensemble.load(str(ensemble_path))
                logger.info("Loaded trained Ensemble model for inference.")
            except Exception as e:
                logger.warning("Could not load ensemble model: %s", e)
        _orchestrator = MainOrchestrator(ensemble_model=ensemble)
    return _orchestrator


class ScamAnalysisRequest(PydanticBaseModel):
    inputType: str = Field(default="message", description="'message', 'url', or 'ocr_text'")
    text: Optional[str] = Field(default=None, description="Raw message text or OCR transcript")
    url: Optional[str] = Field(default=None, description="Target URL if scanning link")
    source: Optional[str] = Field(default="manual", description="'whatsapp', 'extension', or 'manual'")


class ScamAnalysisResponse(PydanticBaseModel):
    verdict: str
    riskScore: int
    confidence: float
    modelResults: Dict[str, Any]
    evidence: List[Dict[str, Any]]
    extractedIndicators: Dict[str, List[str]]
    contradictions: List[str]
    limitations: List[str]
    recommendations: List[str]
    explanation: str
    processingTimeMs: float


@app.get("/health")
def health_check() -> Dict[str, Any]:
    state = StateManager.get_instance()
    keys = ProviderKeyManager.get_instance().get_status()
    return {
        "status": "healthy",
        "service": "scamshield-ml-inference",
        "overall_progress": state.calculate_overall_progress(),
        "key_health": keys,
        "timestamp": time.time(),
    }


@app.get("/api/v1/models/status")
def model_status() -> Dict[str, Any]:
    state = StateManager.get_instance()
    leaderboard = []
    for exp in state.get_experiments():
        leaderboard.append({
            "model": exp.model_name,
            "f1": exp.metrics.get("f1", 0.0),
            "accuracy": exp.metrics.get("accuracy", 0.0),
            "fpr": exp.metrics.get("fpr", 0.0),
        })
    return {
        "models_count": len(leaderboard),
        "leaderboard": leaderboard,
        "next_action": state.get_next_action(),
    }


@app.post("/api/v1/analyze", response_model=ScamAnalysisResponse)
def analyze(req: ScamAnalysisRequest) -> ScamAnalysisResponse:
    target = req.text or req.url or ""
    if not target.strip():
        raise HTTPException(status_code=400, detail="Must provide 'text' or 'url' in payload")

    orchestrator = get_orchestrator()
    res = orchestrator.analyze(target, content_type=req.inputType)

    # Extract indicators
    from scamshield_ml.features.text_features import TextFeatureExtractor
    heuristics = TextFeatureExtractor.extract_heuristics(target)

    return ScamAnalysisResponse(
        verdict=res.verdict,
        riskScore=res.risk_score,
        confidence=res.confidence,
        modelResults={"ml_ensemble": res.ml_prediction} if res.ml_prediction else {},
        evidence=res.evidence,
        extractedIndicators={
            "urls": heuristics["extracted_urls"],
            "phoneNumbers": heuristics["extracted_phones"],
            "upiIds": heuristics["extracted_upis"],
        },
        contradictions=res.contradictions_detected,
        limitations=res.limitations,
        recommendations=res.recommendations,
        explanation=res.human_explanation,
        processingTimeMs=res.processing_time_ms,
    )
