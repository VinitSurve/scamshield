import { RedirectChain, RedirectHop } from '../types/threat';
import { canonicalizeUrl } from '../security/url-validator';
import { extractRootDomain } from '../security/domain-normalizer';
import { CacheService } from '../storage/cache-service';
import { logger } from '../utils/logger';

export class RedirectTracker {
  private static activeChains = new Map<number, RedirectChain>();
  private static readonly MAX_HOPS = 5;

  static recordNavigationStart(tabId: number, rawUrl: string): RedirectChain {
    const canonical = canonicalizeUrl(rawUrl);
    const domain = canonical.domain || '';
    const now = Date.now();

    const chain: RedirectChain = {
      tabId,
      originalUrl: rawUrl,
      originalDomain: domain,
      hops: [
        {
          hopNumber: 1,
          url: rawUrl,
          domain,
          isSuspicious: false,
        },
      ],
      isCrossDomain: false,
      hasSuspiciousHop: false,
      isBlocked: false,
      startedAt: now,
      lastUpdatedAt: now,
    };

    this.activeChains.set(tabId, chain);
    return chain;
  }

  static recordHop(tabId: number, targetUrl: string, statusCode?: number): RedirectChain {
    let chain = this.activeChains.get(tabId);
    if (!chain) {
      return this.recordNavigationStart(tabId, targetUrl);
    }

    const canonical = canonicalizeUrl(targetUrl);
    const domain = canonical.domain || '';
    const hopNumber = chain.hops.length + 1;

    // Check if this hop is cross-domain
    const rootOriginal = extractRootDomain(chain.originalDomain);
    const rootCurrent = extractRootDomain(domain);
    const isCrossDomain = rootOriginal !== '' && rootCurrent !== '' && rootOriginal !== rootCurrent;

    // Check if target domain is known malicious
    const threat = CacheService.checkLocalIntelligence(domain, canonical.canonicalUrl);
    const isThreat = threat !== null && (threat.severity === 'HIGH' || threat.severity === 'CRITICAL');

    const hop: RedirectHop = {
      hopNumber,
      url: targetUrl,
      domain,
      statusCode,
      isSuspicious: isCrossDomain || isThreat || hopNumber > 3,
      reason: isThreat
        ? `Destination is verified threat: ${threat.category}`
        : isCrossDomain
        ? `Cross-domain transition from ${chain.originalDomain} to ${domain}`
        : undefined,
    };

    chain.hops.push(hop);
    chain.finalUrl = targetUrl;
    chain.finalDomain = domain;
    chain.isCrossDomain = chain.isCrossDomain || isCrossDomain;
    chain.hasSuspiciousHop = chain.hasSuspiciousHop || hop.isSuspicious;
    chain.lastUpdatedAt = Date.now();

    // Loop detection
    if (chain.hops.length >= this.MAX_HOPS) {
      logger.warn(`Excessive redirect chain detected on tab ${tabId} (${chain.hops.length} hops)`);
      chain.hasSuspiciousHop = true;
    }

    this.activeChains.set(tabId, chain);
    return chain;
  }

  static getChain(tabId: number): RedirectChain | undefined {
    return this.activeChains.get(tabId);
  }

  static removeChain(tabId: number): void {
    this.activeChains.delete(tabId);
  }
}
