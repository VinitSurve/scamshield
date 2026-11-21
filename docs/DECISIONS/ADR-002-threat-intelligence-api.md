# ADR-002: Threat Intelligence API & Privacy-Preserving Lookups

## Status
Accepted

## Context
Transmitting raw destination URLs from the user's browser to the ScamShield backend introduces severe privacy liabilities (exfiltration of search queries, internal company domains, sensitive authentication tokens in query strings).

## Decision
We implement a **32-bit k-Anonymity prefix hashing protocol** inspired by Google Safe Browsing:
1. The client canonicalizes the domain (stripping path, query parameters, and fragments).
2. The client calculates the full `SHA-256(canonical_domain)`.
3. The client sends only the first 8 hex characters (32 bits) to the endpoint `GET /api/v1/reputation/prefix/{prefix}`.
4. The server returns all active threat records matching that 32-bit prefix.
5. The client checks locally whether the full hash is present in the returned list.

## Consequences
- **Positive:** Mathematical privacy guarantee; backend never learns the specific website the user is visiting; immune to eavesdropping on browsing history.
- **Negative / Tradeoffs:** Slightly higher bandwidth per query (~1-2KB returning multiple hash entries per prefix bucket) compared to a simple boolean response.
