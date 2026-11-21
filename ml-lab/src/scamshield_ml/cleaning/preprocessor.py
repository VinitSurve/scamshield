"""Data Preprocessing & Normalization Engine for ScamShield ML Lab."""

from __future__ import annotations

import json
import logging
import re
import unicodedata
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class DatasetPreprocessor:
    """Cleans, normalizes, and sanitizes multimodal dataset samples."""

    def __init__(
        self,
        raw_path: Optional[Path] = None,
        processed_path: Optional[Path] = None,
    ) -> None:
        base_dir = Path(__file__).resolve().parent.parent.parent.parent
        self.raw_path = raw_path or base_dir / "data" / "raw" / "raw_dataset.json"
        self.processed_path = processed_path or base_dir / "data" / "processed" / "clean_dataset.json"
        self.processed_path.parent.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def normalize_text(text: str) -> str:
        """Normalizes Unicode characters, removes control characters, consolidates whitespace."""
        if not text:
            return ""
        # Unicode normalization (NFC preserves Devanagari combined glyphs properly)
        text = unicodedata.normalize("NFC", text)
        # Convert tabs, carriage returns, and vertical whitespace into spaces first
        text = re.sub(r"[\r\t\f\v]+", " ", text)
        # Replace non-printable / control characters (except newline)
        text = "".join(ch for ch in text if ch == "\n" or unicodedata.category(ch)[0] != "C")
        # Normalize whitespace
        text = re.sub(r"[ ]+", " ", text)
        text = re.sub(r"\n\s*\n+", "\n", text)
        return text.strip()

    @staticmethod
    def normalize_url(url: str) -> str:
        """Normalizes URLs for consistent lexical feature extraction."""
        target = url.strip()
        if not target.lower().startswith(("http://", "https://")):
            target = "https://" + target
        try:
            parsed = urlparse(target)
            scheme = parsed.scheme.lower()
            netloc = parsed.netloc.lower()
            path = parsed.path or "/"
            # Reconstruct
            clean = f"{scheme}://{netloc}{path}"
            if parsed.query:
                clean += f"?{parsed.query}"
            return clean
        except Exception:
            return target

    def process(self, force: bool = False) -> List[Dict[str, Any]]:
        """Cleans all samples from raw dataset and writes to clean_dataset.json."""
        if self.processed_path.exists() and not force:
            logger.info("Loading existing processed dataset from %s", self.processed_path)
            with open(self.processed_path, "r", encoding="utf-8") as f:
                return json.load(f)

        if not self.raw_path.exists():
            raise FileNotFoundError(f"Raw dataset not found at {self.raw_path}. Run collection first.")

        with open(self.raw_path, "r", encoding="utf-8") as f:
            raw_samples = json.load(f)

        clean_samples = []
        for sample in raw_samples:
            content_type = sample.get("content_type", "message")
            raw_content = sample.get("content", "")

            if content_type == "url":
                cleaned_content = self.normalize_url(raw_content)
            else:
                cleaned_content = self.normalize_text(raw_content)

            clean_sample = dict(sample)
            clean_sample["content"] = cleaned_content
            clean_sample["char_length"] = len(cleaned_content)
            clean_sample["word_count"] = len(cleaned_content.split())
            clean_samples.append(clean_sample)

        with open(self.processed_path, "w", encoding="utf-8") as f:
            json.dump(clean_samples, f, indent=2, ensure_ascii=False)

        logger.info("Processed %d samples into %s", len(clean_samples), self.processed_path)
        return clean_samples
