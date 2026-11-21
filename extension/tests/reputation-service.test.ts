import { describe, it, expect, beforeEach, vi } from 'vitest';
import { ReputationService } from '../src/services/reputation-service';
import { SettingsService } from '../src/storage/settings-service';
import { CacheService } from '../src/storage/cache-service';

describe('Reputation Service Master Evaluation Pipeline', () => {
  beforeEach(async () => {
    await CacheService.clearAll();
    await SettingsService.resetSettings();
  });

  it('evaluates confirmed offline phishing domains as blocked CRITICAL threats', async () => {
    const verdict = await ReputationService.evaluateUrl('https://sbi-online-kyc-verification.top/login.php');

    expect(verdict.domain).toBe('sbi-online-kyc-verification.top');
    expect(verdict.severity).toBe('CRITICAL');
    expect(verdict.category).toBe('FAKE_KYC');
    expect(verdict.isBlocked).toBe(true);
    expect(verdict.source).toBe('OFFLINE_RULE');
  });

  it('evaluates Google Safe Browsing malware test URL as blocked CRITICAL MALWARE via path-specific signature', async () => {
    const verdict = await ReputationService.evaluateUrl('https://testsafebrowsing.appspot.com/s/malware.html', true);

    expect(verdict.domain).toBe('testsafebrowsing.appspot.com');
    expect(verdict.canonicalUrl).toBe('https://testsafebrowsing.appspot.com/s/malware.html');
    expect(verdict.severity).toBe('CRITICAL');
    expect(verdict.category).toBe('MALWARE');
    expect(verdict.riskScore).toBeGreaterThanOrEqual(0.95);
    expect(verdict.isBlocked).toBe(true);
    expect(verdict.source).toBe('OFFLINE_RULE');
    expect(verdict.matchedPattern).toBe('testsafebrowsing.appspot.com/s/malware.html');

    const offlineCheck = verdict.checksSummary?.find((c) => c.name === 'OFFLINE_SIGNATURES');
    expect(offlineCheck).toBeDefined();
    expect(offlineCheck?.status).toBe('completed');
    expect(offlineCheck?.result).toBe('FAIL');
    expect(offlineCheck?.inputType).toBe('full_url');
    expect(offlineCheck?.details).toContain('testsafebrowsing.appspot.com/s/malware.html');
  });

  it('evaluates parent root domain testsafebrowsing.appspot.com/ without path as NOT malware (path-level isolation)', async () => {
    const verdict = await ReputationService.evaluateUrl('https://testsafebrowsing.appspot.com/', true);

    expect(verdict.domain).toBe('testsafebrowsing.appspot.com');
    expect(verdict.category).not.toBe('MALWARE');
    expect(verdict.isBlocked).toBe(false);
  });

  it('evaluates unindexed domain with offline threat intelligence as ANALYSIS_UNAVAILABLE with conservative risk score (never CLEAN or 2%)', async () => {
    // Simulate threat intelligence gateway offline / network failure
    const originalFetch = globalThis.fetch;
    (globalThis as any).fetch = vi.fn(async (url: string | URL | Request) => {
      const urlStr = typeof url === 'string' ? url : url.toString();
      if (urlStr.includes('/api/v1/reputation/prefix/')) {
        throw new Error('Connection refused: threat intelligence gateway offline');
      }
      return {
        ok: true,
        status: 200,
        json: async () => ({}),
      };
    });

    try {
      const verdict = await ReputationService.evaluateUrl('https://unindexed-offline-test-site.org/', true);

      expect(verdict.category).toBe('ANALYSIS_UNAVAILABLE');
      expect(verdict.severity).toBe('UNKNOWN');
      expect(verdict.confidence).toBe('LOW');
      expect(verdict.riskScore).toBe(0.20);
      expect(verdict.isBlocked).toBe(false);

      const apiCheck = verdict.checksSummary?.find((c) => c.name === 'GLOBAL_THREAT_API');
      expect(apiCheck).toBeDefined();
      expect(apiCheck?.status).toBe('unavailable');
      expect(apiCheck?.result).toBe('UNAVAILABLE');
      expect(apiCheck?.error).toContain('Connection refused');

      // Crucial assertion: never generates false claim of zero reports when offline!
      const hasFalseCleanClaim = verdict.evidence.some((e) => e.includes('zero malicious reports on record'));
      expect(hasFalseCleanClaim).toBe(false);

      const hasUnavailableWarning = verdict.evidence.some((e) => e.includes('Unavailable') || e.includes('absence of remote data is NOT proof of safety'));
      expect(hasUnavailableWarning).toBe(true);
    } finally {
      (globalThis as any).fetch = originalFetch;
    }
  });

  it('evaluates brand impersonation domains through heuristic analysis', async () => {
    const verdict = await ReputationService.evaluateUrl('https://hdfc-netbanking-verify.xyz/update');

    expect(verdict.domain).toBe('hdfc-netbanking-verify.xyz');
    expect(verdict.severity).toBe('CRITICAL');
    expect(verdict.category).toBe('PHISHING');
    expect(verdict.impersonatedBrand).toBe('HDFC Bank');
    expect(verdict.isBlocked).toBe(true);
    expect(verdict.source).toBe('HEURISTIC');
  });

  it('evaluates Punycode homoglyph domains as suspicious', async () => {
    const verdict = await ReputationService.evaluateUrl('https://xn--80ak6aa92e.com/login');

    expect(verdict.severity).toBe('SUSPICIOUS');
    expect(verdict.isBlocked).toBe(false);
    expect(verdict.evidence[0]).toContain('Punycode');
  });

  it('evaluates Tranco high-trust anchors as safe with zero risk score', async () => {
    const verdict = await ReputationService.evaluateUrl('https://onlinesbi.sbi/portal');

    expect(verdict.severity).toBe('SAFE');
    expect(verdict.riskScore).toBe(0.0);
    expect(verdict.isBlocked).toBe(false);
    expect(verdict.source).toBe('TRANCO_ANCHOR');
  });

  it('evaluates LinkedIn as a verified Tranco anchor with zero risk score and check checklist', async () => {
    const verdict = await ReputationService.evaluateUrl('https://www.linkedin.com/feed/for-you/', true);

    expect(verdict.domain).toBe('www.linkedin.com');
    expect(verdict.severity).toBe('SAFE');
    expect(verdict.category).toBe('LEGITIMATE');
    expect(verdict.riskScore).toBe(0.0);
    expect(verdict.source).toBe('TRANCO_ANCHOR');
    expect(verdict.isBlocked).toBe(false);
    expect(verdict.isFreshScan).toBe(true);
    expect(verdict.scanDurationMs).toBeGreaterThanOrEqual(0);
    expect(verdict.checksSummary?.find((c) => c.name === 'TRANCO_ANCHOR')?.result).toBe('PASS');
  });

  it('evaluates user-whitelisted domains as safe even if otherwise suspicious', async () => {
    await SettingsService.addDomainToWhitelist('custom-test-corp.com');

    const verdict = await ReputationService.evaluateUrl('https://custom-test-corp.com/login');
    expect(verdict.severity).toBe('SAFE');
    expect(verdict.evidence[0]).toContain('whitelisted');
  });

  it('evaluates clean unindexed domains with NO_KNOWN_THREAT and dynamic low risk score when threat intel is active and clean', async () => {
    const verdict = await ReputationService.evaluateUrl('https://unindexed-fresh-domain-99.store/', true);

    expect(verdict.category).toBe('NO_KNOWN_THREAT');
    expect(verdict.riskScore).toBe(0.05);
    expect(verdict.isBlocked).toBe(false);
    expect(verdict.confidence).toBe('MEDIUM');
    expect(verdict.checksSummary).toBeDefined();
    expect(verdict.checksSummary?.length).toBeGreaterThan(0);
    const apiCheck = verdict.checksSummary?.find((c) => c.name === 'GLOBAL_THREAT_API');
    expect(apiCheck?.status).toBe('completed');
    expect(apiCheck?.result).toBe('CLEAN');
  });
});
