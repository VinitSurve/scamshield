import { ReputationService } from '../services/reputation-service';
import { SettingsService } from '../storage/settings-service';
import { RedirectTracker } from './redirect-tracker';
import { isInternalBrowserScheme, canonicalizeUrl } from '../security/url-validator';
import { logger } from '../utils/logger';

export class NavigationMonitor {
  // Ephemeral domain bypass store for deliberate user overrides ("Proceed Anyway")
  private static bypassDomains = new Map<string, number>();

  static initialize(): void {
    // 1. Navigation Interception Hook (Before Navigation Starts)
    chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
      // Only inspect top-level main frame navigation
      if (details.frameId !== 0) return;

      const rawUrl = details.url;
      if (isInternalBrowserScheme(rawUrl)) return;

      const tabId = details.tabId;
      const canonical = canonicalizeUrl(rawUrl);
      const domain = canonical.domain;
      if (!domain) return;

      // Track redirect hops
      RedirectTracker.recordHop(tabId, rawUrl);

      // Check if user previously bypassed this domain
      if (this.isBypassed(domain)) {
        logger.info(`Navigation allowed: Domain ${domain} has active deliberate user bypass`);
        return;
      }

      // Check user protection settings
      const settings = await SettingsService.getSettings();
      if (!settings.protectionEnabled) {
        this.updateBadge(tabId, 'OFF', '#64748b', 'ScamShield Protection Paused');
        return;
      }

      // Evaluate destination reputation
      try {
        const verdict = await ReputationService.evaluateUrl(rawUrl);

        if (verdict.isBlocked && settings.blockMaliciousDomains) {
          logger.warn(`BLOCKING malicious navigation on tab ${tabId}: ${rawUrl} (${verdict.category})`);

          // Redirect to Safe Warning Interstitial
          const interstitialUrl = chrome.runtime.getURL(
            `interstitial.html?url=${encodeURIComponent(rawUrl)}&domain=${encodeURIComponent(domain)}&category=${encodeURIComponent(verdict.category)}&severity=${encodeURIComponent(verdict.severity)}`
          );

          await chrome.tabs.update(tabId, { url: interstitialUrl });
          this.updateBadge(tabId, '🚨', '#ef4444', `Blocked: ${verdict.category}`);
        } else if (verdict.severity === 'SUSPICIOUS' && settings.warnSuspiciousWebsites) {
          this.updateBadge(tabId, '!', '#f59e0b', `Warning: Suspicious Website (${verdict.category})`);
        } else if (verdict.severity === 'SAFE') {
          this.updateBadge(tabId, '✓', '#10b981', 'Protected & Verified Safe');
        } else {
          this.updateBadge(tabId, '', '#64748b', 'ScamShield Active');
        }
      } catch (err) {
        logger.error('Error during navigation reputation check:', err);
      }
    });

    // 2. Navigation Committed Hook (Update final tab badge and status)
    chrome.webNavigation.onCommitted.addListener(async (details) => {
      if (details.frameId !== 0) return;
      if (isInternalBrowserScheme(details.url)) return;

      const tabId = details.tabId;
      const canonical = canonicalizeUrl(details.url);
      if (!canonical.domain) return;

      const verdict = await ReputationService.evaluateUrl(details.url);

      if (verdict.severity === 'SAFE') {
        this.updateBadge(tabId, '✓', '#10b981', 'Protected & Verified Safe');
      } else if (verdict.severity === 'SUSPICIOUS') {
        this.updateBadge(tabId, '!', '#f59e0b', `Warning: Suspicious Website (${verdict.category})`);
      } else if (verdict.severity === 'HIGH' || verdict.severity === 'CRITICAL') {
        this.updateBadge(tabId, '🚨', '#ef4444', `Warning: Dangerous Website (${verdict.category})`);
      } else {
        this.updateBadge(tabId, '', '#64748b', 'ScamShield Active');
      }
    });

    // 3. Tab Closed Hook: Cleanup active redirect chains
    chrome.tabs.onRemoved.addListener((tabId) => {
      RedirectTracker.removeChain(tabId);
    });

    logger.info('NavigationMonitor initialized successfully');
  }

  static grantBypass(domain: string, durationMinutes = 15): void {
    const expiresAt = Date.now() + durationMinutes * 60 * 1000;
    this.bypassDomains.set(domain.toLowerCase().trim(), expiresAt);
    logger.info(`Granted temporary bypass for domain ${domain} for ${durationMinutes} minutes`);
  }

  static isBypassed(domain: string): boolean {
    const clean = domain.toLowerCase().trim();
    const expiry = this.bypassDomains.get(clean);
    if (!expiry) return false;

    if (Date.now() > expiry) {
      this.bypassDomains.delete(clean);
      return false;
    }
    return true;
  }

  private static updateBadge(tabId: number, text: string, color: string, title: string): void {
    try {
      chrome.action.setBadgeText({ tabId, text });
      chrome.action.setBadgeBackgroundColor({ tabId, color });
      chrome.action.setTitle({ tabId, title });
    } catch (err) {
      // Tab may have closed before badge could update
      logger.debug('Badge update ignored for tab', tabId, err);
    }
  }
}
