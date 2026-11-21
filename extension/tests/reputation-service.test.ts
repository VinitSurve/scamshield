import { describe, it, expect, beforeEach } from 'vitest';
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

  it('evaluates clean unindexed domains with NO_KNOWN_THREAT and dynamic low risk score', async () => {
    const verdict = await ReputationService.evaluateUrl('https://unindexed-fresh-domain-99.store/');

    expect(verdict.category).toBe('NO_KNOWN_THREAT');
    expect(verdict.riskScore).toBeLessThanOrEqual(0.05);
    expect(verdict.isBlocked).toBe(false);
    expect(verdict.checksSummary).toBeDefined();
    expect(verdict.checksSummary?.length).toBeGreaterThan(0);
  });
});
