"""Unit tests for Specialized Multi-Agent Intelligence & Main Orchestrator."""

from scamshield_ml.orchestration.agents import (
    BehavioralRedirectAgent,
    DomainIntelligenceAgent,
    HTTPSCertificateAgent,
    IndianScamIntelligenceAgent,
    ThreatIntelligenceAgent,
    URLStructureAgent,
    WebsiteContentAgent,
)
from scamshield_ml.orchestration.orchestrator import MainOrchestrator


def test_url_structure_agent_flags_impersonation():
    agent = URLStructureAgent()
    rep = agent.analyze("https://sbi-online-kyc-verification.top/auth")
    assert rep.verdict in ("malicious", "suspicious")
    assert rep.risk_score >= 70
    assert any(e["indicator"] == "high_risk_disposable_tld" for e in rep.evidence)
    assert any(e["indicator"] == "brand_impersonation_mismatch" for e in rep.evidence)


def test_threat_intelligence_agent_detects_known_malware():
    agent = ThreatIntelligenceAgent()
    rep = agent.analyze("https://testsafebrowsing.appspot.com/s/malware.html")
    assert rep.verdict == "malicious"
    assert rep.risk_score == 98
    assert rep.confidence >= 0.95


def test_domain_intelligence_agent_verifies_trust_anchor():
    agent = DomainIntelligenceAgent()
    rep = agent.analyze("https://onlinesbi.sbi")
    assert rep.verdict == "clean"
    assert rep.risk_score == 0
    assert any(e["indicator"] == "verified_trust_anchor" for e in rep.evidence)


def test_https_agent_disclaimer():
    agent = HTTPSCertificateAgent()
    rep = agent.analyze("https://phishing-site.top")
    assert rep.verdict == "clean"
    assert any("HTTPS alone does not establish" in lim for lim in rep.limitations)


def test_indian_scam_agent_detects_threats():
    agent = IndianScamIntelligenceAgent()

    # Digital arrest
    rep_arrest = agent.analyze("This is Mumbai Police Cyber Crime Branch. A narcotics parcel is registered on your Aadhaar.")
    assert rep_arrest.verdict == "malicious"
    assert any(e["indicator"] == "digital_arrest_coercion" for e in rep_arrest.evidence)

    # Electricity disconnection
    rep_elec = agent.analyze("Priya Grahak, aapka Bijli bill baki hai. Aaj raat electricity disconnect ho jayegi.")
    assert rep_elec.verdict in ("malicious", "suspicious")
    assert any(e["indicator"] == "electricity_disconnection_scam" for e in rep_elec.evidence)

    # UPI collect
    rep_upi = agent.analyze("Rs 2,500 refund approved. Accept collect request and enter UPI PIN to receive money.")
    assert rep_upi.verdict in ("malicious", "suspicious")
    assert any(e["indicator"] == "upi_collect_pin_fraud" for e in rep_upi.evidence)


def test_main_orchestrator_resolves_contradictions_and_verdicts():
    orchestrator = MainOrchestrator()

    # Confirmed threat test page
    res_malware = orchestrator.analyze("https://testsafebrowsing.appspot.com/s/malware.html")
    assert res_malware.verdict == "CONFIRMED_MALICIOUS"
    assert res_malware.risk_score >= 95

    # Verified clean anchor
    res_google = orchestrator.analyze("https://google.com")
    assert res_google.verdict == "VERIFIED_TRUSTED"
    assert res_google.risk_score == 0

    # Contradiction: valid HTTPS on bank phishing URL
    res_phish = orchestrator.analyze("https://sbi-online-kyc.top/verify")
    assert res_phish.verdict in ("HIGH_RISK", "CONFIRMED_MALICIOUS")
    assert len(res_phish.contradictions_detected) >= 1
    assert any("Transport Security Contradiction" in c for c in res_phish.contradictions_detected)


def test_main_orchestrator_plain_text_message_routing_no_fake_domain_or_ssl_error():
    orchestrator = MainOrchestrator()

    # Plain text message starting with 'URGENT:' containing no URL
    msg = "URGENT: Team standup moved to conference room B at 4:30 PM."
    res = orchestrator.analyze(msg)

    # Must NOT report "urgent" as an unverified domain
    evidence_types = [e.get("indicator") for e in res.evidence]
    assert "unverified_domain" not in evidence_types
    # Must NOT flag plain_http_detected (high severity transport security error) on plain text!
    assert "plain_http_detected" not in evidence_types

    # URL-specific agents must be marked skipped
    reports = {r["agent"]: r["status"] for r in res.agent_reports}
    assert reports["domain_intelligence_agent"] == "skipped"
    assert reports["https_certificate_agent"] == "skipped"
    assert reports["url_structure_agent"] == "skipped"
