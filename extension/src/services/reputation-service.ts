import { ReputationVerdict } from '../types/threat';
import { canonicalizeUrl, isPrivateOrLoopbackHost } from '../security/url-validator';
import { detectBrandImpersonation, isPunycode } from '../security/domain-normalizer';
import { sha256Hex, get32BitPrefix } from '../utils/crypto';
import { CacheService } from '../storage/cache-service';
import { SettingsService } from '../storage/settings-service';
import { ApiClient } from './api-client';
import { logger } from '../utils/logger';

export class ReputationService {

  /**
   * Master evaluation function for any URL
   */
  static async evaluateUrl(rawUrl: string, skipCache = false): Promise<ReputationVerdict> {
    const canonical = canonicalizeUrl(rawUrl);

    // 1. Internal browser schemes or invalid URLs
    if (canonical.isInternal || !canonical.isValid || !canonical.domain) {
      return {
        domain: canonical.domain || 'internal',
        canonicalUrl: canonical.canonicalUrl || rawUrl,
        severity: 'SAFE',
        category: 'LEGITIMATE',
        riskScore: 0.0,
        evidence: ['Internal browser or extension page'],
        source: 'OFFLINE_RULE',
        isBlocked: false,
        evaluatedAt: Date.now(),
      };
    }

    const domain = canonical.domain;

    // 2. User Whitelist Check
    const isWhitelisted = await SettingsService.isDomainWhitelisted(domain);
    if (isWhitelisted) {
      return {
        domain,
        canonicalUrl: canonical.canonicalUrl,
        severity: 'SAFE',
        category: 'LEGITIMATE',
        riskScore: 0.0,
        evidence: ['Domain manually whitelisted by user'],
        source: 'LOCAL_CACHE',
        isBlocked: false,
        evaluatedAt: Date.now(),
      };
    }

    // 3. Private / Loopback Host Check
    if (isPrivateOrLoopbackHost(domain)) {
      return {
        domain,
        canonicalUrl: canonical.canonicalUrl,
        severity: 'SAFE',
        category: 'LEGITIMATE',
        riskScore: 0.0,
        evidence: ['Local development or private network address (RFC 1918)'],
        source: 'OFFLINE_RULE',
        isBlocked: false,
        evaluatedAt: Date.now(),
      };
    }

    // 4. Local High-Confidence Intelligence Check (0ms)
    const localVerdict = CacheService.checkLocalIntelligence(domain, canonical.canonicalUrl, skipCache);
    if (localVerdict) {
      return localVerdict;
    }

    if (!skipCache) {
      // Check L2 storage cache
      const cachedStorageVerdict = await CacheService.getFromStorage(domain);
      if (cachedStorageVerdict) {
        return cachedStorageVerdict;
      }
    }

    // 5. Heuristic Brand Impersonation Check
    const impersonation = detectBrandImpersonation(domain);
    if (impersonation.isImpersonating && impersonation.impersonatedBrand) {
      const verdict: ReputationVerdict = {
        domain,
        canonicalUrl: canonical.canonicalUrl,
        severity: 'CRITICAL',
        category: 'PHISHING',
        riskScore: 0.95,
        impersonatedBrand: impersonation.impersonatedBrand,
        evidence: [
          `Domain mimics official brand "${impersonation.impersonatedBrand}"`,
          `Unsanctioned domain containing keyword "${impersonation.matchedKeyword}"`,
          `Official legitimate domains: ${impersonation.legitimateDomains?.join(', ')}`,
        ],
        source: 'HEURISTIC',
        isBlocked: true,
        evaluatedAt: Date.now(),
      };

      await CacheService.set(domain, verdict);
      return verdict;
    }

    // 6. Punycode / IDN Homoglyph Check
    if (isPunycode(domain)) {
      const verdict: ReputationVerdict = {
        domain,
        canonicalUrl: canonical.canonicalUrl,
        severity: 'SUSPICIOUS',
        category: 'PHISHING',
        riskScore: 0.75,
        evidence: [
          'Domain uses Punycode (IDN) representation: possible Cyrillic/Greek homoglyph impersonation attack',
        ],
        source: 'HEURISTIC',
        isBlocked: false,
        evaluatedAt: Date.now(),
      };

      await CacheService.set(domain, verdict);
      return verdict;
    }

    // 7. Privacy-Preserving k-Anonymity Remote Lookup
    try {
      const settings = await SettingsService.getSettings();
      const client = new ApiClient(settings.apiBaseUrl);

      const fullHash = await sha256Hex(domain);
      const prefix = get32BitPrefix(fullHash);

      const remoteData = await client.getPrefixMatches(prefix);

      if (remoteData && remoteData.matches && remoteData.matches.length > 0) {
        // Find if our exact domain hash matches any known threat in the returned prefix bucket
        const matchedThreat = remoteData.matches.find(
          (m) => m.full_hash.toLowerCase() === fullHash.toLowerCase()
        );

        if (matchedThreat) {
          const isBlocked = matchedThreat.severity === 'HIGH' || matchedThreat.severity === 'CRITICAL';
          const verdict: ReputationVerdict = {
            domain,
            canonicalUrl: canonical.canonicalUrl,
            severity: matchedThreat.severity,
            category: matchedThreat.threat_type,
            riskScore: matchedThreat.severity === 'CRITICAL' ? 0.96 : 0.85,
            impersonatedBrand: matchedThreat.impersonated_brand,
            communityReportCount: matchedThreat.reported_count || 1,
            evidence: [
              `Verified threat in ScamShield Global Threat Intelligence Network`,
              `Category: ${matchedThreat.threat_type}`,
              matchedThreat.impersonated_brand ? `Impersonates: ${matchedThreat.impersonated_brand}` : '',
              matchedThreat.reported_count ? `Reported by ${matchedThreat.reported_count} users` : '',
            ].filter(Boolean),
            source: 'REMOTE_API',
            isBlocked,
            evaluatedAt: Date.now(),
          };

          await CacheService.set(domain, verdict);
          return verdict;
        }
      }

      // If in demo mode and domain contains suspicious keywords
      if (settings.demoMode) {
        return this.generateDemoVerdict(domain, canonical.canonicalUrl);
      }
    } catch (err) {
      logger.debug('Remote prefix lookup failed, proceeding to neutral fallback:', err);
    }

    // 8. Unknown Neutral Verdict (Never falsely declare safe when unverified)
    const unknownVerdict: ReputationVerdict = {
      domain,
      canonicalUrl: canonical.canonicalUrl,
      severity: 'UNKNOWN',
      category: 'UNKNOWN',
      riskScore: 0.15,
      evidence: [
        'Domain not found in local or remote malicious threat feeds',
        'No brand impersonation keywords detected',
      ],
      source: 'FALLBACK',
      isBlocked: false,
      evaluatedAt: Date.now(),
    };

    // Cache neutral verdict for a short duration
    await CacheService.set(domain, unknownVerdict);
    return unknownVerdict;
  }

  private static generateDemoVerdict(domain: string, canonicalUrl: string): ReputationVerdict {
    const isPhish = domain.includes('demo-phish') || domain.includes('test-scam');
    if (isPhish) {
      return {
        domain,
        canonicalUrl,
        severity: 'CRITICAL',
        category: 'PHISHING',
        riskScore: 0.99,
        evidence: [
          '[DEMO MODE] Synthetic Threat Intelligence fixture',
          'Simulated banking credential phishing target',
        ],
        impersonatedBrand: 'Synthetic Bank Demo',
        source: 'FALLBACK',
        isBlocked: true,
        evaluatedAt: Date.now(),
      };
    }

    return {
      domain,
      canonicalUrl,
      severity: 'SAFE',
      category: 'LEGITIMATE',
      riskScore: 0.05,
      evidence: ['[DEMO MODE] Domain verified clean in synthetic evaluation'],
      source: 'FALLBACK',
      isBlocked: false,
      evaluatedAt: Date.now(),
    };
  }
}
