import { ReputationVerdict, ThreatCategory, ThreatSeverity } from '../types/threat';
import { canonicalizeUrl, getUrlThreatExpressions } from '../security/url-validator';
import { logger } from '../utils/logger';

export interface CachedReputationEntry {
  verdict: ReputationVerdict;
  cachedAt: number;
  expiresAt: number;
}

// 7 days TTL for cached verdicts
const CACHE_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const CACHE_STORAGE_PREFIX = 'scamshield_rep_';

// Hardened Tranco protected anchors: globally trusted high-traffic platforms that cannot be blocked
export const PROTECTED_TRANCO_ANCHORS = new Set([
  // Global Platforms
  'google.com',
  'google.co.in',
  'youtube.com',
  'apple.com',
  'microsoft.com',
  'github.com',
  'linkedin.com',
  'x.com',
  'twitter.com',
  'facebook.com',
  'instagram.com',
  'whatsapp.com',
  'reddit.com',
  'netflix.com',
  'spotify.com',
  'wikipedia.org',
  'cloudflare.com',
  'stackoverflow.com',
  'zoom.us',
  'yahoo.com',
  'live.com',
  'office.com',
  'bing.com',
  'medium.com',
  'quora.com',
  'dropbox.com',
  'adobe.com',
  'gitlab.com',
  'npmjs.com',
  'telegram.org',

  // Major Indian Services & Banking Anchors
  'amazon.com',
  'amazon.in',
  'flipkart.com',
  'sbi.co.in',
  'onlinesbi.sbi',
  'onlinesbi.com',
  'statebankofindia.com',
  'hdfcbank.com',
  'icicibank.com',
  'axisbank.com',
  'kotak.com',
  'bankofbaroda.in',
  'punjabnationalbank.in',
  'canarabank.com',
  'incometax.gov.in',
  'parivahan.gov.in',
  'uidai.gov.in',
  'epfindia.gov.in',
  'npci.org.in',
  'bhimupi.org.in',
  'rbi.org.in',
  'irctc.co.in',
  'paytm.com',
  'phonepe.com',
  'zomato.com',
  'swiggy.com',
  'hotstar.com',
  'jiocinema.com',
  'zerodha.com',
  'groww.in',
  'cred.club',
  'tata.com',
  'airtel.in',
  'jio.com',
  'makemytrip.com',
]);

// High-confidence offline malicious threat intelligence dataset
// Essential for zero-day protection even when offline or disconnected
export const OFFLINE_MALICIOUS_THREATS: Record<
  string,
  {
    category: ThreatCategory;
    severity: ThreatSeverity;
    evidence: string[];
    impersonatedBrand?: string;
  }
> = {
  'sbi-online-kyc-verification.top': {
    category: 'FAKE_KYC',
    severity: 'CRITICAL',
    impersonatedBrand: 'State Bank of India',
    evidence: [
      'Domain mimics official SBI NetBanking portal',
      'Target of active SMS phishing campaign (Fake KYC lure)',
      'Credential harvesting form detected on non-official TLD (.top)',
    ],
  },
  'fake-challan-pay.online': {
    category: 'GOV_IMPERSONATION',
    severity: 'CRITICAL',
    impersonatedBrand: 'Parivahan eChallan',
    evidence: [
      'Impersonates Ministry of Road Transport & Highways eChallan',
      'Illegitimate payment gateway soliciting fraudulent traffic fines',
    ],
  },
  'electricity-bill-update.xyz': {
    category: 'PHISHING',
    severity: 'HIGH',
    impersonatedBrand: 'MSEDCL / Electricity Board',
    evidence: [
      'Deceptive power disconnection lure ("Bijli bill update")',
      'Unverified registrar and suspicious TLD (.xyz)',
    ],
  },
  'hdfc-kyc-portal.top': {
    category: 'FAKE_KYC',
    severity: 'CRITICAL',
    impersonatedBrand: 'HDFC Bank',
    evidence: [
      'Fake banking KYC update portal harvesting NetBanking passwords & OTP',
      'Domain registered recently with privacy shielding',
    ],
  },
  'paytm-reward-claim.online': {
    category: 'UPI_FRAUD',
    severity: 'HIGH',
    impersonatedBrand: 'PayTM',
    evidence: [
      'Fake cashback scratch card lure prompting malicious UPI auto-debit requests',
    ],
  },
  'free-recharge-offer.store': {
    category: 'LOTTERY_SCAM',
    severity: 'HIGH',
    evidence: [
      'Viral WhatsApp forward scam promising free 3-month mobile recharge',
      'Aggressive ad-redirect hops and contact harvesting',
    ],
  },
  'incometax-refund-gov.top': {
    category: 'GOV_IMPERSONATION',
    severity: 'CRITICAL',
    impersonatedBrand: 'Income Tax Department',
    evidence: [
      'Fictitious tax refund notice demanding bank account & debit card details',
      'Unauthorized use of national emblem iconography',
    ],
  },
  'phish-test.scamshield.org': {
    category: 'PHISHING',
    severity: 'CRITICAL',
    impersonatedBrand: 'ScamShield Security Test Suite',
    evidence: [
      'Reserved synthetic test fixture for automated browser verification',
      'Simulated credential-harvesting environment',
    ],
  },
  // Google Safe Browsing Official Malware Test Fixture (Path-Specific Threat)
  'testsafebrowsing.appspot.com/s/malware.html': {
    category: 'MALWARE',
    severity: 'CRITICAL',
    impersonatedBrand: 'Google Safe Browsing Test Suite',
    evidence: [
      'Standard Google Safe Browsing synthetic malware verification endpoint',
      'Confirmed path-level malicious test fixture for browser protection',
      'Targeted malware distribution test path (/s/malware.html)',
    ],
  },
};

export class CacheService {
  private static l1MemoryCache = new Map<string, CachedReputationEntry>();

  /**
   * Check local offline intelligence first (0ms latency).
   * Hierarchically matches full URL expressions (path-specific) first, then domain-level threats.
   */
  static checkLocalIntelligence(
    domain: string,
    canonicalUrl: string,
    skipDynamicCache = false
  ): ReputationVerdict | null {
    const cleanDomain = domain.toLowerCase().trim();

    // 1. High-Confidence Offline Malicious Threats Check (Hierarchical URL & Domain Matching)
    // Check path-specific and full URL expressions FIRST so path threats on cloud/hosting are not masked
    const canonical = canonicalizeUrl(canonicalUrl);
    const expressions = getUrlThreatExpressions(canonical);

    for (const item of expressions) {
      const expr = item.expression;
      if (OFFLINE_MALICIOUS_THREATS[expr]) {
        const threat = OFFLINE_MALICIOUS_THREATS[expr];
        const isPathSpecific = expr.includes('/');
        return {
          domain: cleanDomain,
          canonicalUrl,
          severity: threat.severity,
          category: threat.category,
          riskScore: 0.98,
          evidence: [
            ...threat.evidence,
            isPathSpecific
              ? `Path-specific threat signature matched: ${expr}`
              : `Domain-level threat signature matched: ${expr}`,
          ],
          impersonatedBrand: threat.impersonatedBrand,
          source: 'OFFLINE_RULE',
          isBlocked: true,
          evaluatedAt: Date.now(),
          matchedPattern: expr,
        };
      }
    }

    // Direct domain fallback check if expressions were empty
    if (OFFLINE_MALICIOUS_THREATS[cleanDomain]) {
      const threat = OFFLINE_MALICIOUS_THREATS[cleanDomain];
      return {
        domain: cleanDomain,
        canonicalUrl,
        severity: threat.severity,
        category: threat.category,
        riskScore: 0.98,
        evidence: threat.evidence,
        impersonatedBrand: threat.impersonatedBrand,
        source: 'OFFLINE_RULE',
        isBlocked: true,
        evaluatedAt: Date.now(),
        matchedPattern: cleanDomain,
      };
    }

    // 2. Tranco Protected Anchor Check
    if (this.isTrancoProtectedAnchor(cleanDomain)) {
      return {
        domain: cleanDomain,
        canonicalUrl,
        severity: 'SAFE',
        category: 'LEGITIMATE',
        riskScore: 0.0,
        evidence: ['Verified High-Trust Anchor Domain (Tranco Top 100K list)'],
        source: 'TRANCO_ANCHOR',
        isBlocked: false,
        evaluatedAt: Date.now(),
      };
    }

    // 3. L1 Memory Cache Check (skipped if skipDynamicCache is true)
    if (!skipDynamicCache) {
      const cacheKey = canonicalUrl && canonicalUrl !== `https://${cleanDomain}/` ? `url_${canonicalUrl}` : cleanDomain;
      const memEntry = this.l1MemoryCache.get(cacheKey) || this.l1MemoryCache.get(cleanDomain);
      if (memEntry && memEntry.expiresAt > Date.now()) {
        return memEntry.verdict;
      }
    }

    return null;
  }

  static isTrancoProtectedAnchor(domain: string): boolean {
    const lower = domain.toLowerCase().trim();
    if (PROTECTED_TRANCO_ANCHORS.has(lower)) return true;

    for (const anchor of PROTECTED_TRANCO_ANCHORS) {
      if (lower.endsWith(`.${anchor}`)) {
        return true;
      }
    }
    return false;
  }

  /**
   * Read from L2 Chrome Local Storage Cache
   */
  static async getFromStorage(domain: string, canonicalUrl?: string): Promise<ReputationVerdict | null> {
    const cleanDomain = domain.toLowerCase().trim();
    const cacheKey = canonicalUrl && canonicalUrl !== `https://${cleanDomain}/` ? `url_${canonicalUrl}` : cleanDomain;
    const key = `${CACHE_STORAGE_PREFIX}${cacheKey}`;

    try {
      const data = await chrome.storage.local.get(key);
      if (data && data[key]) {
        const entry: CachedReputationEntry = data[key];
        if (entry.expiresAt > Date.now()) {
          // Populate L1 cache for fast subsequent hits
          this.l1MemoryCache.set(cacheKey, entry);
          return entry.verdict;
        } else {
          // Expired, delete from storage
          await chrome.storage.local.remove(key);
        }
      }
    } catch (err) {
      logger.warn('Failed to read from local storage cache:', err);
    }

    return null;
  }

  /**
   * Save a verdict into both L1 Memory and L2 Storage Cache
   */
  static async set(domain: string, verdict: ReputationVerdict, canonicalUrl?: string): Promise<void> {
    const cleanDomain = domain.toLowerCase().trim();
    const cacheKey = canonicalUrl && canonicalUrl !== `https://${cleanDomain}/` ? `url_${canonicalUrl}` : cleanDomain;
    const now = Date.now();
    const entry: CachedReputationEntry = {
      verdict,
      cachedAt: now,
      expiresAt: now + CACHE_TTL_MS,
    };

    // Save in L1 memory
    this.l1MemoryCache.set(cacheKey, entry);
    if (cacheKey !== cleanDomain) {
      // If path-specific, do not overwrite domain-level cache
    } else {
      this.l1MemoryCache.set(cleanDomain, entry);
    }

    // Save in L2 chrome storage
    const key = `${CACHE_STORAGE_PREFIX}${cacheKey}`;
    try {
      await chrome.storage.local.set({ [key]: entry });
    } catch (err) {
      logger.warn('Failed to persist cache entry to storage:', err);
    }
  }

  /**
   * Purge all local threat caches
   */
  static async clearAll(): Promise<void> {
    this.l1MemoryCache.clear();
    try {
      const allData = await chrome.storage.local.get(null);
      const keysToRemove = Object.keys(allData).filter((k) => k.startsWith(CACHE_STORAGE_PREFIX));
      if (keysToRemove.length > 0) {
        await chrome.storage.local.remove(keysToRemove);
      }
      logger.info(`Cleared ${keysToRemove.length} cache entries from storage`);
    } catch (err) {
      logger.error('Failed to clear local cache:', err);
    }
  }
}
