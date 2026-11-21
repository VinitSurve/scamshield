"""Structural & Lexical URL Feature Extractor for Dedicated URL Classification."""

from __future__ import annotations

import math
import re
from typing import Any, Dict, List
from urllib.parse import urlparse

SUSPICIOUS_TLDS = {
    "top", "xyz", "tk", "ml", "ga", "cf", "gq", "work", "click",
    "download", "site", "online", "club", "buzz", "rest", "surf"
}

KNOWN_SHORTENERS = {
    "is.gd", "bit.ly", "tinyurl.com", "t.co", "cutt.ly", "rb.gy",
    "v.gd", "shorturl.at", "ow.ly", "buff.ly"
}

INDIAN_BRANDS = {
    "sbi", "onlinesbi", "hdfc", "hdfcbank", "icici", "icicibank",
    "axis", "axisbank", "pnb", "bob", "kotak", "yono", "phonepe",
    "paytm", "gpay", "googlepay", "bhim", "aadhaar", "uidai",
    "incometax", "challan", "echallan", "bijli", "mahavitaran",
    "bses", "indiapost"
}

LEGIT_HOST_SUFFIXES = {
    "sbi.co.in", "onlinesbi.sbi", "hdfcbank.com", "icicibank.com",
    "axisbank.com", "pnbindia.in", "kotak.com", "bankofbaroda.in",
    "phonepe.com", "paytm.com", "google.com", "google.co.in",
    "amazon.in", "amazon.com", "flipkart.com", "apple.com",
    "microsoft.com", "github.com", "cybercrime.gov.in", "rbi.org.in",
    "incometax.gov.in", "indiapost.gov.in", "uidai.gov.in",
    "mahadiscom.in", "irctc.co.in"
}


def shannon_entropy(data: str) -> float:
    """Calculates Shannon entropy of a string."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    counts: Dict[str, int] = {}
    for ch in data:
        counts[ch] = counts.get(ch, 0) + 1
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)


class URLFeatureExtractor:
    """Extracts 20 numerical and boolean security features from a URL."""

    FEATURE_NAMES = [
        "url_length",
        "host_length",
        "path_length",
        "query_length",
        "num_dots",
        "num_hyphens",
        "num_underscores",
        "num_slashes",
        "num_digits",
        "num_special_chars",
        "digit_ratio",
        "is_https",
        "is_ip_literal",
        "has_punycode",
        "is_shortener",
        "suspicious_tld",
        "has_port",
        "has_brand_keyword",
        "brand_mismatch",
        "host_entropy",
    ]

    @classmethod
    def extract_features(cls, url: str) -> Dict[str, Any]:
        target = (url or "").strip()
        # Find URL inside target if present
        match = re.search(r"https?://[^\s<>\"'()]+", target)
        if match:
            target = match.group(0)
        else:
            # If target contains spaces or newlines, there is no valid URL in this string
            if " " in target or "\n" in target:
                target = ""
            elif "." in target and not target.endswith("."):
                target = "https://" + target
            else:
                target = ""

        hostname = ""
        path = ""
        query = ""
        has_port = 0
        is_https = 0

        if target:
            try:
                parsed = urlparse(target)
                try:
                    hostname = parsed.hostname or ""
                except (ValueError, TypeError):
                    hostname = ""
                path = parsed.path or ""
                query = parsed.query or ""
                is_https = 1 if parsed.scheme == "https" else 0
                try:
                    has_port = 1 if parsed.port and parsed.port not in (80, 443) else 0
                except (ValueError, TypeError):
                    has_port = 0
            except Exception:
                hostname = ""
                path = ""
                query = ""

        host_lower = hostname.lower()
        path_lower = path.lower()
        full_lower = target.lower()

        # Check IP literal
        is_ip = 1 if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", host_lower) else 0

        # Check punycode
        has_punycode = 1 if "xn--" in host_lower else 0

        # Check shortener
        is_shortener = 1 if host_lower in KNOWN_SHORTENERS else 0

        # Check suspicious TLD
        tld = host_lower.split(".")[-1] if "." in host_lower else ""
        suspicious_tld = 1 if tld in SUSPICIOUS_TLDS else 0

        # Check brand keywords
        has_brand = 0
        for b in INDIAN_BRANDS:
            if b in full_lower:
                has_brand = 1
                break

        # Check brand mismatch: brand mentioned in URL, but domain is NOT the official domain
        brand_mismatch = 0
        if has_brand and host_lower:
            is_official = any(host_lower == leg or host_lower.endswith("." + leg) for leg in LEGIT_HOST_SUFFIXES)
            if not is_official:
                brand_mismatch = 1

        digits_count = sum(ch.isdigit() for ch in target)
        special_chars = sum(ch in "@#$%^&*=+~`|" for ch in target)

        return {
            "url_length": len(target),
            "host_length": len(hostname),
            "path_length": len(path),
            "query_length": len(query),
            "num_dots": target.count("."),
            "num_hyphens": target.count("-"),
            "num_underscores": target.count("_"),
            "num_slashes": target.count("/"),
            "num_digits": digits_count,
            "num_special_chars": special_chars,
            "digit_ratio": round(digits_count / max(1, len(target)), 4) if target else 0.0,
            "is_https": is_https,
            "is_ip_literal": is_ip,
            "has_punycode": has_punycode,
            "is_shortener": is_shortener,
            "suspicious_tld": suspicious_tld,
            "has_port": has_port,
            "has_brand_keyword": has_brand,
            "brand_mismatch": brand_mismatch,
            "host_entropy": shannon_entropy(host_lower),
        }

    @classmethod
    def to_vector(cls, features: Dict[str, Any]) -> List[float]:
        return [float(features.get(name, 0.0)) for name in cls.FEATURE_NAMES]
