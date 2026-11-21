# ADR-006: Minimalist Browser Permission Strategy

## Status
Accepted

## Context
Requesting broad browser permissions (such as `<all_urls>`, `webRequest`, `cookies`, `management`, `nativeMessaging`) damages user trust, triggers intense Chrome Web Store review scrutiny, and enlarges the extension's attack surface if compromised.

## Decision
We enforce a strict **Least-Privilege Manifest V3 permission model**:
1. **Mandatory Permissions Declared:**
   - `storage`: For storing local threat caches, user preferences, and offline Bloom filter bits.
   - `webNavigation`: For detecting `onBeforeNavigate` domain transitions and redirect hops.
   - `alarms`: For periodic background synchronization of threat delta updates.
2. **Eliminated / Prohibited Permissions:**
   - ❌ `cookies`: Prohibited; zero cookie inspection needed.
   - ❌ `history`: Prohibited; browsing history is never traversed.
   - ❌ `webRequestBlocking`: Prohibited by MV3.
   - ❌ `<all_urls>` Content Script Injection: Content scripts are scoped or triggered via `activeTab` or explicit match patterns (e.g., `https://mail.google.com/*` for webmail).

## Consequences
- **Positive:** Maximum user trust; swift Chrome Web Store approval; zero exposure of browser cookies or general browsing history.
- **Negative / Tradeoffs:** Content scripts cannot proactively run on every page without user activation or specific scoped domain declarations.
