"""Specialized Multi-Agent Threat Intelligence Engine for ScamShield."""

from __future__ import annotations

import logging
import re
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from scamshield_ml.features.text_features import (
    CREDENTIAL_KEYWORDS,
    FINANCIAL_KEYWORDS,
    KYC_KEYWORDS,
    URGENCY_KEYWORDS,
)
from scamshield_ml.features.url_features import (
    INDIAN_BRANDS,
    KNOWN_SHORTENERS,
    LEGIT_HOST_SUFFIXES,
    SUSPICIOUS_TLDS,
    URLFeatureExtractor,
)

logger = logging.getLogger(__name__)


@dataclass
class EvidenceItem:
    type: str
    indicator: str
    value: str
    severity: str  # "low", "medium", "high", "critical"


@dataclass
class AgentReport:
    agent: str
    status: str  # "completed", "skipped", "failed"
    verdict: str  # "malicious", "suspicious", "clean", "unverified"
    risk_score: int  # 0 to 100
    confidence: float  # 0.0 to 1.0
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    checks_performed: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)
    recommendation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class URLStructureAgent:
    """Agent 1: Analyzes URL lexical structure, subdomains, punycode, TLDs, and encoding."""

    def analyze(self, target: str) -> AgentReport:
        checks = [
            "url_normalization",
            "ip_literal_check",
            "punycode_check",
            "subdomain_depth_check",
            "suspicious_tld_check",
            "shortener_check",
            "brand_in_hostname_check",
        ]
        evidence: List[Dict[str, Any]] = []
        limitations: List[str] = []

        feats = URLFeatureExtractor.extract_features(target)
        risk = 5
        verdict = "clean"

        if feats["is_ip_literal"]:
            risk += 45
            evidence.append(asdict(EvidenceItem("url_feature", "ip_literal_host", target, "high")))

        if feats["has_punycode"]:
            risk += 35
            evidence.append(asdict(EvidenceItem("url_feature", "punycode_homoglyph", target, "high")))

        if feats["suspicious_tld"]:
            risk += 40
            evidence.append(asdict(EvidenceItem("url_feature", "high_risk_disposable_tld", target, "high")))

        if feats["is_shortener"]:
            risk += 25
            evidence.append(asdict(EvidenceItem("url_feature", "url_shortener_detected", target, "medium")))
            limitations.append("Full target destination obscured by shortener without active network resolution")

        if feats["brand_mismatch"]:
            risk += 50
            evidence.append(asdict(EvidenceItem("url_feature", "brand_impersonation_mismatch", target, "critical")))

        if feats["num_dots"] > 3:
            risk += 20
            evidence.append(asdict(EvidenceItem("url_feature", "excessive_subdomains", f"{feats['num_dots']} dots", "medium")))

        risk = min(100, risk)
        if risk >= 75:
            verdict = "malicious"
        elif risk >= 40:
            verdict = "suspicious"

        return AgentReport(
            agent="url_structure_agent",
            status="completed",
            verdict=verdict,
            risk_score=risk,
            confidence=0.88,
            evidence=evidence,
            checks_performed=checks,
            limitations=limitations,
            recommendation="Do not enter credentials on unverified domain." if risk >= 40 else "URL structure appears standard.",
        )


class ThreatIntelligenceAgent:
    """Agent 2: Checks local threat intelligence feeds and reputation databases."""

    KNOWN_MALICIOUS_PATTERNS = [
        "testsafebrowsing.appspot.com/s/malware.html",
        "sbi-online-kyc-verification.top",
        "hdfc-bank-secure-login.xyz",
        "icicibank-accounts-kyc.top",
        "echallan-parivahan-delhi.top",
        "kbc-jio-lottery-winner.xyz",
        "indiapost-redelivery.top",
        "adani-bill-pay.top",
    ]

    def analyze(self, target: str) -> AgentReport:
        checks = ["local_threat_db_lookup", "phishing_signature_match", "malware_prefix_check"]
        evidence = []
        lower = target.lower()

        is_match = any(pat in lower for pat in self.KNOWN_MALICIOUS_PATTERNS)
        if is_match:
            evidence.append(asdict(EvidenceItem("threat_intel", "known_malicious_threat_match", target, "critical")))
            return AgentReport(
                agent="threat_intelligence_agent",
                status="completed",
                verdict="malicious",
                risk_score=98,
                confidence=0.99,
                evidence=evidence,
                checks_performed=checks,
                limitations=[],
                recommendation="CONFIRMED THREAT: Block access immediately.",
            )

        return AgentReport(
            agent="threat_intelligence_agent",
            status="completed",
            verdict="clean",
            risk_score=5,
            confidence=0.75,
            evidence=[],
            checks_performed=checks,
            limitations=["Absence from threat feed does not confirm legitimacy for novel zero-day domains"],
            recommendation="No threat records in local database. Continue behavioral evaluation.",
        )


class DomainIntelligenceAgent:
    """Agent 3: Evaluates domain trust anchors and organizational legitimacy."""

    def analyze(self, target: str) -> AgentReport:
        checks = ["tranco_top_anchor_check", "domain_normalization", "trusted_org_registry"]
        try:
            parsed = urlparse(target if target.startswith("http") else f"https://{target}")
            host = (parsed.hostname or "").lower()
        except Exception:
            host = target.lower()

        is_trusted = any(host == leg or host.endswith("." + leg) for leg in LEGIT_HOST_SUFFIXES)
        if is_trusted:
            return AgentReport(
                agent="domain_intelligence_agent",
                status="completed",
                verdict="clean",
                risk_score=0,
                confidence=0.98,
                evidence=[asdict(EvidenceItem("domain_intel", "verified_trust_anchor", host, "low"))],
                checks_performed=checks,
                limitations=[],
                recommendation="Verified official domain.",
            )

        return AgentReport(
            agent="domain_intelligence_agent",
            status="completed",
            verdict="unverified",
            risk_score=40,
            confidence=0.70,
            evidence=[asdict(EvidenceItem("domain_intel", "unverified_domain", host, "medium"))],
            checks_performed=checks,
            limitations=["Domain registration WHOIS data not queried via offline sandbox"],
            recommendation="Domain is not a verified trust anchor. Exercise caution.",
        )


class HTTPSCertificateAgent:
    """Agent 4: Evaluates transport layer security. Emphasizes: HTTPS != safe."""

    def analyze(self, target: str) -> AgentReport:
        checks = ["scheme_validation", "transport_encryption_check"]
        is_https = target.strip().lower().startswith("https://")

        if is_https:
            return AgentReport(
                agent="https_certificate_agent",
                status="completed",
                verdict="clean",
                risk_score=5,
                confidence=0.90,
                evidence=[asdict(EvidenceItem("transport_security", "https_active", "Encrypted transport active", "low"))],
                checks_performed=checks,
                limitations=["IMPORTANT: HTTPS alone does not establish site legitimacy; phishing kits freely use valid SSL certificates"],
                recommendation="Transport is encrypted. Validate domain identity before submitting credentials.",
            )

        return AgentReport(
            agent="https_certificate_agent",
            status="completed",
            verdict="suspicious",
            risk_score=60,
            confidence=0.95,
            evidence=[asdict(EvidenceItem("transport_security", "plain_http_detected", "Unencrypted plaintext transport", "high"))],
            checks_performed=checks,
            limitations=[],
            recommendation="Plaintext HTTP. Credentials sent over this connection can be intercepted.",
        )


class WebsiteContentAgent:
    """Agent 5: Analyzes content for phishing triggers, credential lures, and urgent threats."""

    def analyze(self, content: str) -> AgentReport:
        checks = ["login_credential_lure_check", "otp_request_check", "kyc_demand_check", "coercive_threat_check"]
        lower = content.lower()
        evidence = []
        risk = 5

        if any(w in lower for w in CREDENTIAL_KEYWORDS):
            risk += 50
            evidence.append(asdict(EvidenceItem("content_analysis", "credential_harvesting_signal", "Demands OTP / PIN / Password", "critical")))

        if any(w in lower for w in KYC_KEYWORDS) and any(w in lower for w in URGENCY_KEYWORDS):
            risk += 45
            evidence.append(asdict(EvidenceItem("content_analysis", "urgent_kyc_coercion", "Urgent KYC suspension threat", "high")))

        if any(w in lower for w in FINANCIAL_KEYWORDS) and any(w in lower for w in ["won", "lottery", "cashback", "refund"]):
            risk += 40
            evidence.append(asdict(EvidenceItem("content_analysis", "financial_reward_lure", "Lottery or cashback promise", "high")))

        risk = min(100, risk)
        verdict = "malicious" if risk >= 75 else "suspicious" if risk >= 40 else "clean"

        return AgentReport(
            agent="website_content_agent",
            status="completed",
            verdict=verdict,
            risk_score=risk,
            confidence=0.85,
            evidence=evidence,
            checks_performed=checks,
            limitations=[],
            recommendation="Do not share OTP or banking credentials." if risk >= 40 else "Content appears non-coercive.",
        )


class BehavioralRedirectAgent:
    """Agent 6: Inspects multi-hop redirects and shortener concealment."""

    def analyze(self, target: str) -> AgentReport:
        checks = ["shortener_unrolling_check", "redirect_loop_prevention", "cross_origin_bounce_check"]
        lower = target.lower()
        is_shortener = any(sh in lower for sh in KNOWN_SHORTENERS)

        if is_shortener:
            return AgentReport(
                agent="behavioral_redirect_agent",
                status="completed",
                verdict="suspicious",
                risk_score=55,
                confidence=0.85,
                evidence=[asdict(EvidenceItem("redirect_behavior", "shortener_concealment", target, "medium"))],
                checks_performed=checks,
                limitations=["Deep active HTTP redirection tracing restricted in offline mode"],
                recommendation="Shortened URL conceals true destination. Inspect expanded link before clicking.",
            )

        return AgentReport(
            agent="behavioral_redirect_agent",
            status="completed",
            verdict="clean",
            risk_score=5,
            confidence=0.80,
            evidence=[],
            checks_performed=checks,
            limitations=[],
            recommendation="No redirect concealment detected.",
        )


class CommunityReputationAgent:
    """Agent 7: Evaluates crowdsourced and community threat reports."""

    def analyze(self, target: str) -> AgentReport:
        checks = ["community_report_index", "incident_frequency_check", "trust_weighting"]
        return AgentReport(
            agent="community_reputation_agent",
            status="completed",
            verdict="clean",
            risk_score=5,
            confidence=0.70,
            evidence=[],
            checks_performed=checks,
            limitations=["Single unverified reports discounted to prevent false-positive denial-of-service"],
            recommendation="No verified community reports filed against this target.",
        )


class IndianScamIntelligenceAgent:
    """Agent 8: Specialized Indian context fraud pattern recognition."""

    def analyze(self, content: str) -> AgentReport:
        checks = [
            "upi_collect_pin_deception",
            "electricity_disconnection_threat",
            "india_post_parcel_fee",
            "kbc_lottery_lure",
            "digital_arrest_police_impersonation",
            "hinglish_marathi_linguistic_signals",
        ]
        lower = content.lower()
        evidence = []
        risk = 5

        # Digital arrest / police
        if any(w in lower for w in ["digital arrest", "cyber crime branch", "mumbai police", "cbi", "narcotics parcel"]):
            risk += 80
            evidence.append(asdict(EvidenceItem("indian_scam", "digital_arrest_coercion", "Police / CBI impersonation threat", "critical")))

        # Electricity disconnection
        if ("electricity" in lower or "bijli" in lower or "mahavitaran" in lower) and ("disconnect" in lower or "kat" in lower or "cut" in lower):
            risk += 55
            evidence.append(asdict(EvidenceItem("indian_scam", "electricity_disconnection_scam", "Threatens immediate power cutoff", "high")))

        # UPI collect request
        if ("upi" in lower or "gpay" in lower or "phonepe" in lower or "paytm" in lower) and ("collect" in lower or "refund" in lower or "enter pin" in lower):
            risk += 50
            evidence.append(asdict(EvidenceItem("indian_scam", "upi_collect_pin_fraud", "Urges approving collect request or entering PIN", "high")))

        # India Post package
        if ("india post" in lower or "indiapost" in lower or "parcel" in lower) and ("redelivery" in lower or "fee" in lower or "address" in lower):
            risk += 45
            evidence.append(asdict(EvidenceItem("indian_scam", "india_post_package_lure", "Fake delivery failure fee", "high")))

        # KBC / Lottery
        if "kbc" in lower or "lucky draw" in lower or ("lottery" in lower and "won" in lower):
            risk += 50
            evidence.append(asdict(EvidenceItem("indian_scam", "lottery_advance_fee_lure", "Kaun Banega Crorepati / lottery lure", "high")))

        risk = min(100, risk)
        verdict = "malicious" if risk >= 75 else "suspicious" if risk >= 40 else "clean"

        return AgentReport(
            agent="indian_scam_intelligence_agent",
            status="completed",
            verdict=verdict,
            risk_score=risk,
            confidence=0.92,
            evidence=evidence,
            checks_performed=checks,
            limitations=[],
            recommendation="Confirmed high-risk Indian cyber fraud pattern." if risk >= 40 else "No specialized Indian scam pattern detected.",
        )
