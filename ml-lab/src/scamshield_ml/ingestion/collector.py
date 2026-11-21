"""India-First Cybersecurity Dataset Collector & Ingestion Engine for Dataset v3.

Orchestrates multi-category, multilingual cybersecurity sample collection:
- Indian banking KYC scams (SBI, HDFC, ICICI, Axis, PNB, BoB, Canara, Kotak)
- UPI collect & QR code payment deception (Google Pay, PhonePe, Paytm, BHIM)
- Electricity & utility disconnection threats (MSEDCL, BESCOM, Tata Power, BSES)
- India Post & courier redelivery fees (India Post, Blue Dart, DTDC, Delhivery)
- KBC & lottery prize lures
- Part-time job / YouTube task scams
- Digital arrest & police / CBI / ED impersonation
- Predatory loan app advance-fee extortion
- OTP theft & credential harvesting
- Legitimate bank alerts, OTPs, delivery notifications, utility bills, and personal communications
Across English, Hindi (Devanagari), Marathi (Devanagari), Hinglish, and Romanized Marathi.
"""

from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from scamshield_ml.ingestion.v3.generator import DatasetV3Builder

logger = logging.getLogger(__name__)


@dataclass
class DatasetSample:
    sample_id: str
    content: str
    content_type: str  # "message", "url", "ocr_text"
    label: str  # "scam", "legitimate", "suspicious"
    is_scam: int  # 1 for scam/suspicious, 0 for legitimate
    category: str
    language: str  # "en", "hi", "mr", "hinglish", "romanized_mr"
    source: str
    extracted_urls: List[str]
    extracted_phones: List[str]
    extracted_upis: List[str]
    synthetic: bool = False
    brand: Optional[str] = None
    explanation: str = ""
    confidence: float = 1.0
    timestamp: str = "2026-11-22T04:30:00Z"
    dataset_version: str = "v3.0.0"


class DatasetCollector:
    """Collects and seeds the ScamShield India-First Cybersecurity Dataset."""

    def __init__(self, raw_data_path: Optional[Path] = None) -> None:
        if raw_data_path is None:
            raw_data_path = Path(__file__).resolve().parent.parent.parent.parent / "data" / "raw" / "raw_dataset.json"
        self.raw_data_path = raw_data_path
        self.raw_data_path.parent.mkdir(parents=True, exist_ok=True)

    def collect(self, force: bool = False) -> List[DatasetSample]:
        """Collects raw dataset samples, persisting to disk."""
        if self.raw_data_path.exists() and not force:
            logger.info("Loading existing raw dataset from %s", self.raw_data_path)
            try:
                with open(self.raw_data_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    return [DatasetSample(**item) for item in data]
            except Exception as e:
                logger.warning("Failed to load existing raw dataset: %s. Re-generating.", e)

        samples = self._generate_representative_dataset()
        with open(self.raw_data_path, "w", encoding="utf-8") as f:
            json.dump([asdict(s) for s in samples], f, indent=2, ensure_ascii=False)
        logger.info("Saved %d raw dataset samples to %s", len(samples), self.raw_data_path)
        return samples

    def _generate_representative_dataset(self) -> List[DatasetSample]:
        """Assembles comprehensive multi-category, multilingual cybersecurity samples for Dataset v3."""
        builder = DatasetV3Builder()
        v3_samples = builder.assemble()
        return [
            DatasetSample(
                sample_id=s.sample_id,
                content=s.content,
                content_type=s.content_type,
                label=s.label,
                is_scam=s.is_scam,
                category=s.category,
                language=s.language,
                source=s.source,
                extracted_urls=s.extracted_urls,
                extracted_phones=s.extracted_phones,
                extracted_upis=s.extracted_upis,
                synthetic=s.synthetic,
                brand=s.brand,
                explanation=s.explanation,
                confidence=s.confidence,
                timestamp=s.timestamp,
                dataset_version=s.dataset_version,
            )
            for s in v3_samples
        ]
