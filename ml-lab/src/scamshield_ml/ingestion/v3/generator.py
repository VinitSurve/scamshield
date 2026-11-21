"""Dataset v3 Master Synthesis & Assembly Engine for ScamShield ML Lab.

Assembles the multimodal India-First Cybersecurity Dataset v3:
- Preserves verified historical v2 foundation
- Incorporates extensive hard-negative corpus (banking, OTPs, UPI, utilities, logistics, personal)
- Incorporates multi-category scam corpus across 22 threat typologies
- Incorporates expanded adversarial benchmark corpus
- Applies SHA-256 deduplication and strict schema validation
- Outputs clean, structured DatasetSample objects versioned as v3.0.0
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from scamshield_ml.ingestion.v3.adversarial_corpus import generate_adversarial_corpus
from scamshield_ml.ingestion.v3.hard_negatives import generate_hard_negatives
from scamshield_ml.ingestion.v3.scam_corpus import generate_scam_corpus

logger = logging.getLogger(__name__)


@dataclass
class DatasetSampleV3:
    sample_id: str
    content: str
    content_type: str  # "message", "url", "ocr_text"
    label: str  # "scam", "legitimate", "suspicious"
    is_scam: int  # 1 or 0
    category: str
    language: str  # "en", "hi", "mr", "hinglish", "romanized_mr"
    source: str
    extracted_urls: List[str]
    extracted_phones: List[str]
    extracted_upis: List[str]
    synthetic: bool
    brand: Optional[str]
    explanation: str
    confidence: float
    timestamp: str
    dataset_version: str


class DatasetV3Builder:
    """Orchestrates the creation and quality-control of Dataset v3."""

    def __init__(self, v2_clean_path: Optional[Path] = None) -> None:
        base_dir = Path(__file__).resolve().parent.parent.parent.parent.parent
        self.v2_clean_path = v2_clean_path or base_dir / "data" / "versions" / "v2.0.0" / "clean_dataset.json"

    def assemble(self) -> List[DatasetSampleV3]:
        """Assembles all components into a single deduplicated, validated v3 dataset."""
        raw_items: List[Dict[str, Any]] = []

        # 1. Historical v2 samples
        if self.v2_clean_path.exists():
            try:
                with open(self.v2_clean_path, "r", encoding="utf-8") as f:
                    v2_data = json.load(f)
                    for item in v2_data:
                        raw_items.append(dict(item))
            except Exception as e:
                logger.warning("Could not read v2 dataset: %s", e)

        # 2. Hard Negatives Corpus
        raw_items.extend(generate_hard_negatives())

        # 3. Comprehensive Scam Corpus
        raw_items.extend(generate_scam_corpus())

        # 4. Adversarial Corpus
        raw_items.extend(generate_adversarial_corpus())

        # 5. Deduplication & Standardization
        seen_hashes = set()
        deduped_samples: List[DatasetSampleV3] = []
        counter = 1

        for item in raw_items:
            content = str(item.get("content", "")).strip()
            if not content:
                continue

            # Normalized hash for deduplication
            content_norm = " ".join(content.split()).lower()
            chash = hashlib.sha256(content_norm.encode("utf-8")).hexdigest()
            if chash in seen_hashes:
                continue
            seen_hashes.add(chash)

            lbl = str(item.get("label", "scam")).lower()
            if lbl not in ("scam", "legitimate", "suspicious"):
                lbl = "scam" if item.get("is_scam") == 1 else "legitimate"
            is_scam_val = 1 if lbl in ("scam", "suspicious") else 0

            cat = str(item.get("category", "UNKNOWN")).upper()
            lang = str(item.get("language", "en")).lower()
            ctype = str(item.get("content_type", "message")).lower()
            if ctype not in ("message", "url", "ocr_text"):
                ctype = "url" if content.startswith(("http://", "https://")) else "message"

            src = str(item.get("source", "curated_threat_intel"))
            synthetic_flag = bool(item.get("synthetic", True))
            brand_val = item.get("brand")
            explanation_val = str(item.get("explanation", ""))
            confidence_val = float(item.get("confidence", 1.0))

            deduped_samples.append(
                DatasetSampleV3(
                    sample_id=f"SCAM-V3-{counter:05d}",
                    content=content,
                    content_type=ctype,
                    label=lbl,
                    is_scam=is_scam_val,
                    category=cat,
                    language=lang,
                    source=src,
                    extracted_urls=item.get("extracted_urls", []),
                    extracted_phones=item.get("extracted_phones", []),
                    extracted_upis=item.get("extracted_upis", []),
                    synthetic=synthetic_flag,
                    brand=brand_val,
                    explanation=explanation_val,
                    confidence=confidence_val,
                    timestamp="2026-11-22T04:30:00Z",
                    dataset_version="v3.0.0",
                )
            )
            counter += 1

        return deduped_samples
