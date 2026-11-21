# ADR-005: Hybrid Multilingual Scam Analysis Architecture

## Status
Accepted

## Context
Indian digital scams predominantly feature Romanized Hindi (Hinglish), Marathi, and mixed-script code-switching. Standard English keyword models fail completely, and automated translation-first pipelines (e.g., Google Translate before evaluation) destroy colloquial nuances, mangle Indian names/UPI entities, and add 300ms of latency.

## Decision
We reject translation-first in favor of a **multi-stage hybrid pipeline**:
1. **Unicode NFKC & De-obfuscation:** Strip zero-width spaces, normalize homoglyphs/confusables.
2. **Deterministic & Phonetic Vernacular Rules:** Match Romanized urgency markers (*"aaj hi"*, *"turant"*, *"power cut honar"*, *"bijli bill"*) directly on raw transliterated text.
3. **Entity Extraction:** Parse Indian 10-digit mobile numbers, UPI handles (`*@okhdfcbank`), and short URLs.
4. **Multilingual Indic LLM Inference:** Native Indic language models evaluate contextual intent without translation.
5. **Localized Explanations:** Explanations generated in the user's preferred language (English, Hindi, Marathi).

## Consequences
- **Positive:** Preserves cultural and linguistic nuance; avoids translation latency; highly accurate on Indian dialect scams.
- **Negative / Tradeoffs:** Requires maintaining localized phonetic/vernacular dictionaries and testing on code-switched corpora.
