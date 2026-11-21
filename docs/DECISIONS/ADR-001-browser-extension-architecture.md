# ADR-001: Chrome Manifest V3 Browser Extension Architecture

## Status
Accepted

## Context
Google Chrome and Chromium browsers enforce Manifest V3 (MV3) for all modern extensions. Key constraints include the deprecation of persistent background pages in favor of event-driven service workers, the elimination of synchronous `webRequestBlocking`, and strict Content Security Policies forbidding remote code execution.

## Decision
1. **Lifecycle Management:** We adopt an event-driven Service Worker architecture with state re-hydration from `chrome.storage.local` and IndexedDB.
2. **Hybrid Navigation Gating:**
   - **Offline Fast Path:** Pre-compiled high-confidence rules and local Bloom filter allow instant local blocking.
   - **Dynamic Asynchronous Path:** We utilize `chrome.webNavigation.onBeforeNavigate` combined with `chrome.tabs.update` redirecting to an internal interstitial (`chrome-extension://<id>/interstitial.html`) when a domain hash matches verified threat intelligence.
3. **Frontend Stack:** The popup and interstitial views are built using **React 19**, **TypeScript**, and **Tailwind CSS**, compiled statically via **Vite**.

## Consequences
- **Positive:** Full compatibility with Chrome Web Store MV3 enforcement; zero memory leaks from persistent background pages; fast, modular UI components.
- **Negative / Tradeoffs:** Cannot synchronously pause HTTP requests indefinitely pending remote network calls; requires local caching and fast prefix hashing (<50ms) to prevent race conditions during page load.
