"""Unit tests for Dataset Collection, Preprocessing, Validation, and Leakage Prevention."""

import tempfile
from pathlib import Path
import pytest
from scamshield_ml.cleaning.preprocessor import DatasetPreprocessor
from scamshield_ml.ingestion.collector import DatasetCollector
from scamshield_ml.validation.validator import DatasetValidator


def test_dataset_collection_generates_samples():
    with tempfile.TemporaryDirectory() as tmpdir:
        raw_path = Path(tmpdir) / "raw.json"
        collector = DatasetCollector(raw_data_path=raw_path)
        samples = collector.collect(force=True)

        assert len(samples) >= 80
        categories = {s.category for s in samples}
        assert "BANKING_KYC" in categories
        assert "UPI_FRAUD" in categories
        assert "ELECTRICITY" in categories
        assert "DELIVERY" in categories
        assert "LEGITIMATE" in categories or any(c.startswith("LEGITIMATE") for c in categories)

        languages = {s.language for s in samples}
        assert "en" in languages
        assert "hi" in languages
        assert "mr" in languages
        assert "hinglish" in languages


def test_dataset_preprocessing_normalizes():
    raw_text = "  Dear Customer,\n\nYour   SBI\taccount is blocked!   "
    clean = DatasetPreprocessor.normalize_text(raw_text)
    assert clean == "Dear Customer,\nYour SBI account is blocked!"

    url = "HTTP://SBI-ONLINE.TOP/auth/ "
    clean_url = DatasetPreprocessor.normalize_url(url)
    assert clean_url == "http://sbi-online.top/auth/"


def test_validator_split_and_zero_leakage():
    with tempfile.TemporaryDirectory() as tmpdir:
        raw_path = Path(tmpdir) / "raw.json"
        processed_path = Path(tmpdir) / "clean.json"

        collector = DatasetCollector(raw_data_path=raw_path)
        collector.collect(force=True)

        preprocessor = DatasetPreprocessor(raw_path=raw_path, processed_path=processed_path)
        preprocessor.process(force=True)

        validator = DatasetValidator(processed_path=processed_path)
        validator.data_dir = Path(tmpdir) / "splits"
        validator.data_dir.mkdir(parents=True, exist_ok=True)
        validator.datasets_dir = Path(tmpdir) / "datasets"
        validator.reports_dir = Path(tmpdir) / "reports"

        manifest = validator.validate_and_split()

        assert manifest["quality_metrics"]["data_leakage_detected"] is False
        assert manifest["splits"]["train_count"] > 0
        assert manifest["splits"]["val_count"] > 0
        assert manifest["splits"]["test_count"] > 0
