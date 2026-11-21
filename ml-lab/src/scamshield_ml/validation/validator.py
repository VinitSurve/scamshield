"""Dataset Quality Validation, Deduplication, and Leakage-Free Splitting Engine."""

from __future__ import annotations

import hashlib
import json
import logging
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


def char_ngrams(text: str, n: int = 3) -> Set[str]:
    """Extracts character n-grams from text."""
    clean = text.lower().replace(" ", "")
    if len(clean) < n:
        return {clean}
    return {clean[i : i + n] for i in range(len(clean) - n + 1)}


def jaccard_similarity(set_a: Set[str], set_b: Set[str]) -> float:
    """Calculates Jaccard similarity between two sets."""
    if not set_a and not set_b:
        return 1.0
    union = len(set_a.union(set_b))
    if union == 0:
        return 0.0
    return len(set_a.intersection(set_b)) / union


class DatasetValidator:
    """Validates dataset integrity, checks near-duplicates, prevents leakage, and splits data."""

    def __init__(self, processed_path: Optional[Path] = None) -> None:
        base_dir = Path(__file__).resolve().parent.parent.parent.parent
        self.base_dir = base_dir
        self.processed_path = processed_path or base_dir / "data" / "processed" / "clean_dataset.json"
        self.datasets_dir = base_dir / "datasets"
        self.reports_dir = base_dir / "reports"
        self.data_dir = base_dir / "data" / "processed"

        self.datasets_dir.mkdir(parents=True, exist_ok=True)
        self.reports_dir.mkdir(parents=True, exist_ok=True)

    def validate_and_split(self) -> Dict[str, Any]:
        """Runs deduplication, data validation, leakage checks, and stratified train/val/test split."""
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.datasets_dir.mkdir(parents=True, exist_ok=True)
        self.reports_dir.mkdir(parents=True, exist_ok=True)

        if not self.processed_path.exists():
            raise FileNotFoundError(f"Clean dataset not found at {self.processed_path}")

        with open(self.processed_path, "r", encoding="utf-8") as f:
            samples: List[Dict[str, Any]] = json.load(f)

        total_input_count = len(samples)

        # 1. Exact Deduplication
        seen_hashes = set()
        unique_samples = []
        duplicate_count = 0

        for s in samples:
            content_hash = hashlib.sha256(s["content"].strip().encode("utf-8")).hexdigest()
            if content_hash in seen_hashes:
                duplicate_count += 1
                continue
            seen_hashes.add(content_hash)
            s["sha256"] = content_hash
            unique_samples.append(s)

        # 2. Near-Duplicate Check
        near_duplicates_found = 0
        ngrams_cache = [char_ngrams(s["content"]) for s in unique_samples]
        for i in range(len(unique_samples)):
            for j in range(i + 1, len(unique_samples)):
                if unique_samples[i]["is_scam"] == unique_samples[j]["is_scam"]:
                    sim = jaccard_similarity(ngrams_cache[i], ngrams_cache[j])
                    if sim > 0.88:
                        near_duplicates_found += 1

        # 3. Label & Schema Validation
        invalid_labels = 0
        missing_fields = 0
        for s in unique_samples:
            if s.get("is_scam") not in (0, 1):
                invalid_labels += 1
            if not s.get("content") or not s.get("category"):
                missing_fields += 1

        # 4. Stratified Split (70% train, 15% val, 15% test) without leakage
        # Group by (category, is_scam)
        groups: Dict[Tuple[str, int], List[Dict[str, Any]]] = {}
        for s in unique_samples:
            key = (s.get("category", "UNKNOWN"), s.get("is_scam", 0))
            groups.setdefault(key, []).append(s)

        train_set: List[Dict[str, Any]] = []
        val_set: List[Dict[str, Any]] = []
        test_set: List[Dict[str, Any]] = []

        import random
        rng = random.Random(42)  # Fixed reproducible seed

        for key, group_samples in groups.items():
            rng.shuffle(group_samples)
            n = len(group_samples)
            n_train = max(1, int(n * 0.70))
            n_val = max(1, int(n * 0.15)) if n >= 3 else 0

            train_set.extend(group_samples[:n_train])
            val_set.extend(group_samples[n_train : n_train + n_val])
            test_set.extend(group_samples[n_train + n_val :])

        # If test_set is empty for tiny group, balance
        if not test_set and len(val_set) > 1:
            test_set.append(val_set.pop())

        # 5. Data Leakage Verification
        train_hashes = {s["sha256"] for s in train_set}
        val_hashes = {s["sha256"] for s in val_set}
        test_hashes = {s["sha256"] for s in test_set}

        leakage_val = len(train_hashes.intersection(val_hashes))
        leakage_test = len(train_hashes.intersection(test_hashes))
        leakage_test_val = len(val_hashes.intersection(test_hashes))
        has_leakage = (leakage_val + leakage_test + leakage_test_val) > 0

        # Save splits
        with open(self.data_dir / "train.json", "w", encoding="utf-8") as f:
            json.dump(train_set, f, indent=2, ensure_ascii=False)
        with open(self.data_dir / "val.json", "w", encoding="utf-8") as f:
            json.dump(val_set, f, indent=2, ensure_ascii=False)
        with open(self.data_dir / "test.json", "w", encoding="utf-8") as f:
            json.dump(test_set, f, indent=2, ensure_ascii=False)

        # 6. Statistical Distributions
        lang_dist = Counter(s.get("language", "unknown") for s in unique_samples)
        cat_dist = Counter(s.get("category", "unknown") for s in unique_samples)
        class_dist = Counter("scam" if s["is_scam"] == 1 else "legitimate" for s in unique_samples)
        type_dist = Counter(s.get("content_type", "message") for s in unique_samples)

        dataset_hash = hashlib.sha256(
            json.dumps([s["sha256"] for s in unique_samples], sort_keys=True).encode()
        ).hexdigest()[:12]

        manifest = {
            "dataset_name": "ScamShield-IndiaFirst-Cybersecurity-Benchmark",
            "version": f"v1.0.0-{dataset_hash}",
            "dataset_hash": dataset_hash,
            "created_at": "2026-11-22T00:00:00Z",
            "total_samples": len(unique_samples),
            "splits": {
                "train_count": len(train_set),
                "val_count": len(val_set),
                "test_count": len(test_set),
            },
            "class_distribution": dict(class_dist),
            "language_distribution": dict(lang_dist),
            "category_distribution": dict(cat_dist),
            "content_type_distribution": dict(type_dist),
            "quality_metrics": {
                "raw_inputs": total_input_count,
                "duplicates_removed": duplicate_count,
                "near_duplicate_pairs": near_duplicates_found,
                "invalid_labels": invalid_labels,
                "missing_fields": missing_fields,
                "data_leakage_detected": has_leakage,
            },
        }

        # Write manifest and schema
        with open(self.datasets_dir / "dataset_manifest.json", "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2)

        schema = {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "title": "ScamShieldDatasetSample",
            "type": "object",
            "required": ["sample_id", "content", "content_type", "label", "is_scam", "category", "language"],
            "properties": {
                "sample_id": {"type": "string"},
                "content": {"type": "string"},
                "content_type": {"type": "string", "enum": ["message", "url", "ocr_text"]},
                "label": {"type": "string", "enum": ["scam", "legitimate", "suspicious"]},
                "is_scam": {"type": "integer", "enum": [0, 1]},
                "category": {"type": "string"},
                "language": {"type": "string"},
                "source": {"type": "string"},
                "extracted_urls": {"type": "array", "items": {"type": "string"}},
                "extracted_phones": {"type": "array", "items": {"type": "string"}},
                "extracted_upis": {"type": "array", "items": {"type": "string"}},
            },
        }
        with open(self.datasets_dir / "schema.json", "w", encoding="utf-8") as f:
            json.dump(schema, f, indent=2)

        # Write quality report
        report_md = f"""# ScamShield Dataset Quality & Leakage Audit Report

- **Dataset Name:** ScamShield-IndiaFirst-Cybersecurity-Benchmark
- **Version:** `{manifest['version']}`
- **Dataset Hash:** `{manifest['dataset_hash']}`
- **Total Unique Samples:** {len(unique_samples)}
- **Raw Inputs Processed:** {total_input_count}
- **Duplicates Purged:** {duplicate_count}
- **Near-Duplicate Pairs Flagged:** {near_duplicates_found}
- **Data Leakage Check:** {'PASSED (Zero Overlap)' if not has_leakage else 'FAILED (Overlap Detected)'}

---

## 1. Split Distribution
| Split | Sample Count | Percentage |
|---|---|---|
| **Train** | {len(train_set)} | {len(train_set) / len(unique_samples) * 100:.1f}% |
| **Validation** | {len(val_set)} | {len(val_set) / len(unique_samples) * 100:.1f}% |
| **Test** | {len(test_set)} | {len(test_set) / len(unique_samples) * 100:.1f}% |

---

## 2. Class Distribution
| Class | Count | Ratio |
|---|---|---|
| **Scam / Malicious (1)** | {class_dist['scam']} | {class_dist['scam'] / len(unique_samples) * 100:.1f}% |
| **Legitimate (0)** | {class_dist['legitimate']} | {class_dist['legitimate'] / len(unique_samples) * 100:.1f}% |

---

## 3. Language Diversity Breakdown
| Language | Samples | Ratio |
|---|---|---|
"""
        for lang, cnt in lang_dist.items():
            report_md += f"| `{lang}` | {cnt} | {cnt / len(unique_samples) * 100:.1f}% |\n"

        report_md += "\n---\n\n## 4. Threat Category Breakdown\n| Category | Count |\n|---|---|\n"
        for cat, cnt in cat_dist.items():
            report_md += f"| `{cat}` | {cnt} |\n"

        report_md += "\n---\n\n## 5. Leakage Prevention Verification\n"
        report_md += f"- Exact matches between Train and Test: **{leakage_test}**\n"
        report_md += f"- Exact matches between Train and Val: **{leakage_val}**\n"
        report_md += f"- Exact matches between Val and Test: **{leakage_test_val}**\n"
        report_md += "- Hash verification algorithm: `SHA-256` content hashing\n"

        with open(self.reports_dir / "dataset_quality_report.md", "w", encoding="utf-8") as f:
            f.write(report_md)

        return manifest
