"""Main Orchestrator for Multi-Agent Threat Intelligence & Evidence-Based Scoring."""

from __future__ import annotations

import logging
import time
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional

from scamshield_ml.orchestration.agents import (
    BehavioralRedirectAgent,
    CommunityReputationAgent,
    DomainIntelligenceAgent,
    HTTPSCertificateAgent,
    IndianScamIntelligenceAgent,
    ThreatIntelligenceAgent,
    URLStructureAgent,
    WebsiteContentAgent,
)

logger = logging.getLogger(__name__)


@dataclass
class OrchestratedThreatResult:
    input_text: str
    input_type: str  # "message", "url", "ocr_text"
    verdict: str  # "CONFIRMED_MALICIOUS", "HIGH_RISK", "SUSPICIOUS", "UNVERIFIED", "NO_KNOWN_THREAT", "VERIFIED_TRUSTED"
    risk_score: int  # 0 to 100
    confidence: float  # 0.0 to 1.0
    ml_prediction: Optional[Dict[str, Any]]
    agent_reports: List[Dict[str, Any]]
    evidence: List[Dict[str, Any]]
    contradictions_detected: List[str]
    limitations: List[str]
    recommendations: List[str]
    human_explanation: str
    processing_time_ms: float

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class MainOrchestrator:
    """Orchestrates deterministic security checks, specialized agents, and ML inference."""

    def __init__(self, ensemble_model: Optional[Any] = None) -> None:
        self.url_agent = URLStructureAgent()
        self.threat_intel_agent = ThreatIntelligenceAgent()
        self.domain_agent = DomainIntelligenceAgent()
        self.https_agent = HTTPSCertificateAgent()
        self.content_agent = WebsiteContentAgent()
        self.redirect_agent = BehavioralRedirectAgent()
        self.community_agent = CommunityReputationAgent()
        self.indian_scam_agent = IndianScamIntelligenceAgent()
        self.ensemble = ensemble_model

    def analyze(self, target: str, content_type: Optional[str] = None) -> OrchestratedThreatResult:
        start_time = time.time()
        trimmed = target.strip()

        # 1. Determine input type
        if content_type is None:
            if trimmed.startswith(("http://", "https://", "www.")) or (len(trimmed.split()) == 1 and "." in trimmed):
                content_type = "url"
            else:
                content_type = "message"

        agent_reports = []
        evidence = []
        contradictions = []
        limitations = []

        # 2. Invoke Specialized Agents
        rep_threat = self.threat_intel_agent.analyze(trimmed)
        agent_reports.append(rep_threat.to_dict())
        evidence.extend(rep_threat.evidence)
        limitations.extend(rep_threat.limitations)

        rep_domain = self.domain_agent.analyze(trimmed)
        agent_reports.append(rep_domain.to_dict())
        evidence.extend(rep_domain.evidence)
        limitations.extend(rep_domain.limitations)

        rep_https = self.https_agent.analyze(trimmed)
        agent_reports.append(rep_https.to_dict())
        evidence.extend(rep_https.evidence)
        limitations.extend(rep_https.limitations)

        rep_url = self.url_agent.analyze(trimmed)
        agent_reports.append(rep_url.to_dict())
        evidence.extend(rep_url.evidence)
        limitations.extend(rep_url.limitations)

        rep_content = self.content_agent.analyze(trimmed)
        agent_reports.append(rep_content.to_dict())
        evidence.extend(rep_content.evidence)
        limitations.extend(rep_content.limitations)

        rep_redirect = self.redirect_agent.analyze(trimmed)
        agent_reports.append(rep_redirect.to_dict())
        evidence.extend(rep_redirect.evidence)
        limitations.extend(rep_redirect.limitations)

        rep_indian = self.indian_scam_agent.analyze(trimmed)
        agent_reports.append(rep_indian.to_dict())
        evidence.extend(rep_indian.evidence)
        limitations.extend(rep_indian.limitations)

        # 3. Run ML Model Prediction if available
        ml_result = None
        if self.ensemble is not None and getattr(self.ensemble, "is_trained", False):
            try:
                pred = self.ensemble.predict_one(trimmed)
                ml_result = {
                    "is_scam": pred.is_scam,
                    "scam_probability": pred.scam_probability,
                    "confidence": pred.confidence,
                    "model_name": pred.model_name,
                    "features_used": pred.features_used,
                }
            except Exception as e:
                logger.warning("ML prediction failed: %s", e)
                limitations.append(f"ML inference error: {e}")

        # 4. Evidence-Aware Aggregation & Contradiction Resolution
        # Rule A: Threat intelligence confirmed match overrides everything
        if rep_threat.verdict == "malicious":
            verdict = "CONFIRMED_MALICIOUS"
            risk_score = 98
            confidence = 0.99
            explanation = "Target is confirmed malicious in global threat intelligence databases."
            recommendations = ["BLOCK access immediately.", "Do NOT navigate or submit any data."]
        # Rule B: Verified trust anchor (e.g. google.com, sbi.co.in)
        elif rep_domain.verdict == "clean" and rep_threat.verdict == "clean" and rep_url.verdict == "clean" and rep_content.verdict == "clean" and rep_indian.verdict == "clean":
            verdict = "VERIFIED_TRUSTED"
            risk_score = 0
            confidence = 0.98
            explanation = "Domain is verified in ScamShield trusted organization directory."
            recommendations = ["Legitimate destination.", "Ensure HTTPS remains active."]
        # Rule C: Indian scam pattern or severe content coercion
        elif rep_indian.verdict == "malicious" or rep_content.verdict == "malicious" or rep_url.verdict == "malicious":
            verdict = "HIGH_RISK"
            risk_score = max(rep_indian.risk_score, rep_content.risk_score, rep_url.risk_score, 88)
            confidence = 0.92
            explanation = "High-risk scam pattern detected. Urges immediate financial action, OTP disclosure, or credential submission."
            recommendations = [
                "Do NOT click any links or call numbers provided.",
                "NEVER share OTP, passwords, or UPI PIN.",
                "Report suspicious communication to National Cyber Crime Helpline: 1930.",
            ]
        elif rep_url.verdict == "suspicious" or rep_content.verdict == "suspicious" or rep_redirect.verdict == "suspicious":
            verdict = "SUSPICIOUS"
            risk_score = max(rep_url.risk_score, rep_content.risk_score, rep_redirect.risk_score, 55)
            confidence = 0.75
            explanation = "Suspicious signals detected: Unverified links, shorteners, or urgency tactics present."
            recommendations = ["Exercise caution.", "Verify sender identity through official channels."]
        else:
            verdict = "NO_KNOWN_THREAT"
            risk_score = 5
            confidence = 0.80
            explanation = "Standard communication. No known malicious indicators detected."
            recommendations = ["Stay vigilant.", "Legitimate organizations never ask for passwords or OTPs."]

        # 5. Check Contradictions
        # Contradiction: Valid HTTPS but malicious content
        if rep_https.verdict == "clean" and verdict in ("CONFIRMED_MALICIOUS", "HIGH_RISK"):
            contradictions.append(
                "Transport Security Contradiction: Connection uses valid HTTPS encryption, but target content or domain exhibits active phishing lures. Valid TLS does NOT indicate site legitimacy."
            )

        # Contradiction: Clean threat DB but bank impersonation
        if rep_threat.verdict == "clean" and rep_url.verdict == "malicious":
            contradictions.append(
                "Threat Feed Contradiction: Target is absent from static threat intelligence feeds, but local heuristics detected active brand impersonation."
            )

        # Contradiction: ML model disagrees with heuristics
        if ml_result:
            ml_scam = ml_result["is_scam"] == 1
            rule_scam = verdict in ("CONFIRMED_MALICIOUS", "HIGH_RISK")
            if ml_scam != rule_scam:
                contradictions.append(
                    f"Model-Heuristic Discrepancy: ML predicted is_scam={ml_scam} (p={ml_result['scam_probability']:.2f}) while security heuristics evaluated verdict={verdict}."
                )

        duration_ms = (time.time() - start_time) * 1000.0

        return OrchestratedThreatResult(
            input_text=target,
            input_type=content_type,
            verdict=verdict,
            risk_score=risk_score,
            confidence=confidence,
            ml_prediction=ml_result,
            agent_reports=agent_reports,
            evidence=evidence,
            contradictions_detected=contradictions,
            limitations=list(set(limitations)),
            recommendations=recommendations,
            human_explanation=explanation,
            processing_time_ms=round(duration_ms, 2),
        )
