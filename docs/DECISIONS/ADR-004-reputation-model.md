# ADR-004: Multi-Signal Community Reputation Scoring Engine

## Status
Accepted

## Context
A community-driven threat database without abuse defense is vulnerable to competitor brigading, Sybil bot attacks, and extortion, where attackers mass-report legitimate domains to force automated blacklisting.

## Decision
1. **Protected Anchors:** The Tranco Top 100K global domains are hardcoded as immune to automated blocking. Reports against them are flagged for human review only.
2. **Exponential Time Decay:** Community reports decay with a 7-day half-life ($\lambda = \frac{\ln(2)}{7 \text{ days}}$), preventing permanent stigma for domains that remediated compromises.
3. **Reporter Trust Weighting:** Dynamic weighting based on submission history ($T \in [0.1, 1.0]$); false-positive submitters are penalized toward zero.
4. **Multi-Factor Requirement:** High-risk block decisions require automated corroboration (e.g., domain age, credential harvest forms) in addition to community reports.

## Consequences
- **Positive:** Mathematically resistant to Sybil attacks and mass-reporting campaigns.
- **Negative / Tradeoffs:** Slightly slower time-to-block for brand new zero-hour domains if reports from unauthenticated users are the only signal.
