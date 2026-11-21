# ADR-003: Isolated URL Investigation Execution Environment

## Status
Accepted

## Context
When users request deep URL investigation via WhatsApp or the extension, the target URL may attempt Server-Side Request Forgery (SSRF), DNS rebinding, internal subnet port scanning, or malicious browser exploits.

## Decision
1. **Disposable Container Sandbox:** Automated investigations run inside ephemeral, unprivileged Docker containers (`--read-only`, no root, 512MB RAM cap, 15-second timeout).
2. **Hardened DNS & IP Pinning:** Pre-flight DNS resolution blocks RFC 1918 private IPs, loopback, and cloud metadata (`169.254.169.254`). HTTP sockets connect directly to the pinned IP with Host and TLS SNI headers.
3. **Hop-by-Hop Redirect Validation:** Every HTTP/JS redirect undergoes full DNS and IP validation prior to following the hop.
4. **Zero Persistent Secrets:** The runner container possesses no access to backend database credentials, cloud IAM keys, or WhatsApp tokens.

## Consequences
- **Positive:** Complete isolation of untrusted target execution; robust prevention of cloud metadata exfiltration and internal network scanning.
- **Negative / Tradeoffs:** Requires a containerized worker dispatcher infrastructure (Redis BullMQ + worker host).
