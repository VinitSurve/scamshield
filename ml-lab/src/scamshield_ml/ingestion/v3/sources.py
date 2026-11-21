"""Data Sources and Provenance Metadata Registry for ScamShield ML Lab Dataset v3.

Documenting provenance, license terms, collection methodology, and synthetic flags
in strict compliance with cybersecurity research ethics and privacy standards.
No real PII, credentials, or victim identities are retained.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional


@dataclass(frozen=True)
class DataSourceProvenance:
    source_id: str
    name: str
    authority_or_publisher: str
    url: Optional[str]
    license_terms: str
    collection_date: str
    collection_method: str
    synthetic: bool
    description: str
    confidence_level: float


DATA_SOURCES: Dict[str, DataSourceProvenance] = {
    "cert_in_advisories": DataSourceProvenance(
        source_id="cert_in_advisories",
        name="CERT-In Cyber Security Alerts & Vulnerability Notes",
        authority_or_publisher="Indian Computer Emergency Response Team (MeitY)",
        url="https://www.cert-in.org.in/",
        license_terms="Government of India Open Access / Public Awareness",
        collection_date="2026-11-22",
        collection_method="Curated from public CERT-In advisories on phishing, APK malware, and UPI scams",
        synthetic=False,
        description="Public threat advisories identifying trending Indian cyber fraud campaigns and indicator patterns.",
        confidence_level=1.0,
    ),
    "rbi_kehta_hai": DataSourceProvenance(
        source_id="rbi_kehta_hai",
        name="RBI Kehta Hai Public Awareness Campaign",
        authority_or_publisher="Reserve Bank of India (RBI)",
        url="https://www.rbi.org.in/",
        license_terms="Public Domain Consumer Education",
        collection_date="2026-11-22",
        collection_method="Official RBI public awareness messages and SMS alerts warning consumers against fraud",
        synthetic=False,
        description="Authentic hard-negative educational messages cautioning citizens against sharing OTPs and UPI PINs.",
        confidence_level=1.0,
    ),
    "npci_safety": DataSourceProvenance(
        source_id="npci_safety",
        name="NPCI UPI Safety Shield & Fraud Awareness",
        authority_or_publisher="National Payments Corporation of India (NPCI)",
        url="https://www.npci.org.in/",
        license_terms="Public Domain Consumer Guidance",
        collection_date="2026-11-22",
        collection_method="Curated from NPCI UPI safety advisories, transactional notification guides, and fraud guidelines",
        synthetic=False,
        description="Standard legitimate UPI collect request notifications, transactional alerts, and safety advisories.",
        confidence_level=1.0,
    ),
    "cybercrime_gov_in": DataSourceProvenance(
        source_id="cybercrime_gov_in",
        name="National Cyber Crime Reporting Portal (1930 / I4C)",
        authority_or_publisher="Ministry of Home Affairs, Government of India",
        url="https://cybercrime.gov.in/",
        license_terms="Public Domain Awareness",
        collection_date="2026-11-22",
        collection_method="Curated scam typologies (Digital Arrest, Fedex courier, Task scams, Electricity bills)",
        synthetic=False,
        description="Authentic threat categories and reported Modus Operandi documented by I4C.",
        confidence_level=1.0,
    ),
    "tranco_top_indian": DataSourceProvenance(
        source_id="tranco_top_indian",
        name="Tranco Top 1M & Official Indian Institutional Domains",
        authority_or_publisher="Tranco List & NIC GoI Web Directory",
        url="https://tranco-list.eu/",
        license_terms="Research / Creative Commons",
        collection_date="2026-11-22",
        collection_method="Curated legitimate institutional domains (.gov.in, .nic.in, .sbi, .bank)",
        synthetic=False,
        description="High-reputation anchor domains for legitimate Indian banking, utilities, and public infrastructure.",
        confidence_level=1.0,
    ),
    "curated_telecom_banking_sms": DataSourceProvenance(
        source_id="curated_telecom_banking_sms",
        name="Authentic Transactional SMS & DLT Notification Corpus",
        authority_or_publisher="Indian Telecom TRAI DLT Headers (SBI, HDFC, ICICI, BESCOM, MSEDCL)",
        url=None,
        license_terms="Sanitized Research Corpus / No PII",
        collection_date="2026-11-22",
        collection_method="DLT-registered SMS notification templates with PII replaced by standardized synthetic placeholders",
        synthetic=False,
        description="Real Indian bank, utility, and courier notification templates containing real transactional phrasing.",
        confidence_level=0.98,
    ),
    "synthetic_adversarial_generator": DataSourceProvenance(
        source_id="synthetic_adversarial_generator",
        name="ScamShield Adversarial Mutation Engine",
        authority_or_publisher="ScamShield ML Lab",
        url=None,
        license_terms="Proprietary / Open Research",
        collection_date="2026-11-22",
        collection_method="Programmatic adversarial mutation using Unicode homoglyphs, zero-width characters, and domain spoofing",
        synthetic=True,
        description="Adversarial stress-test samples testing robustness against evasion and edge-case legitimate phrasing.",
        confidence_level=0.95,
    ),
    "synthetic_multilingual_corpus": DataSourceProvenance(
        source_id="synthetic_multilingual_corpus",
        name="ScamShield Multilingual Indian Fraud Corpus v3",
        authority_or_publisher="ScamShield ML Lab",
        url=None,
        license_terms="Proprietary / Open Research",
        collection_date="2026-11-22",
        collection_method="Programmatic template synthesis adhering to regional linguistic patterns (Hindi, Marathi, Hinglish)",
        synthetic=True,
        description="High-coverage contextual synthesis for underrepresented Indic dialects and emerging scam typologies.",
        confidence_level=0.95,
    ),
}
