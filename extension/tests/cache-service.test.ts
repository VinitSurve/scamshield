import { describe, it, expect, beforeEach } from 'vitest';
import { CacheService } from '../src/storage/cache-service';

describe('Threat Cache Service & Tranco Anchor Protection', () => {
  beforeEach(async () => {
    await CacheService.clearAll();
  });

  it('recognizes Tranco top anchors as permanently protected and safe', () => {
    const googleVerdict = CacheService.checkLocalIntelligence('google.com', 'https://google.com/');
    expect(googleVerdict).not.toBeNull();
    expect(googleVerdict?.severity).toBe('SAFE');
    expect(googleVerdict?.source).toBe('TRANCO_ANCHOR');
    expect(googleVerdict?.isBlocked).toBe(false);

    const sbiVerdict = CacheService.checkLocalIntelligence('onlinesbi.sbi', 'https://onlinesbi.sbi/');
    expect(sbiVerdict).not.toBeNull();
    expect(sbiVerdict?.severity).toBe('SAFE');
    expect(sbiVerdict?.source).toBe('TRANCO_ANCHOR');
  });

  it('instantly identifies known high-confidence offline malicious threats', () => {
    const fakeSbi = CacheService.checkLocalIntelligence(
      'sbi-online-kyc-verification.top',
      'https://sbi-online-kyc-verification.top/'
    );
    expect(fakeSbi).not.toBeNull();
    expect(fakeSbi?.severity).toBe('CRITICAL');
    expect(fakeSbi?.category).toBe('FAKE_KYC');
    expect(fakeSbi?.isBlocked).toBe(true);

    const fakeChallan = CacheService.checkLocalIntelligence(
      'fake-challan-pay.online',
      'https://fake-challan-pay.online/'
    );
    expect(fakeChallan).not.toBeNull();
    expect(fakeChallan?.severity).toBe('CRITICAL');
    expect(fakeChallan?.isBlocked).toBe(true);
  });

  it('returns null for unindexed domains to trigger remote/heuristic evaluation', () => {
    const unknown = CacheService.checkLocalIntelligence('random-shop-123.store', 'https://random-shop-123.store/');
    expect(unknown).toBeNull();
  });

  it('persists and retrieves verdicts to/from L1 memory and L2 storage', async () => {
    const testVerdict = {
      domain: 'test-cached-domain.com',
      canonicalUrl: 'https://test-cached-domain.com/',
      severity: 'SUSPICIOUS' as const,
      category: 'PHISHING' as const,
      riskScore: 0.85,
      evidence: ['Manual test entry'],
      source: 'LOCAL_CACHE' as const,
      isBlocked: false,
      evaluatedAt: Date.now(),
    };

    await CacheService.set('test-cached-domain.com', testVerdict);

    const retrieved = await CacheService.getFromStorage('test-cached-domain.com');
    expect(retrieved).not.toBeNull();
    expect(retrieved?.domain).toBe('test-cached-domain.com');
    expect(retrieved?.riskScore).toBe(0.85);
  });
});
