import { describe, it, expect, beforeEach } from 'vitest';
import { CONTROLLED_TEST_CASES } from '../src/test-lab/test-cases';
import { TestRunner } from '../src/test-lab/test-runner';
import { CacheService } from '../src/storage/cache-service';
import { SettingsService } from '../src/storage/settings-service';

describe('Security Test Lab — Automated Verification Suite', () => {
  beforeEach(async () => {
    await CacheService.clearAll();
    await SettingsService.resetSettings();
  });

  it('contains exactly 20 predefined controlled test cases covering all security and AI categories', () => {
    expect(CONTROLLED_TEST_CASES).toHaveLength(20);

    const categories = new Set(CONTROLLED_TEST_CASES.map((tc) => tc.categoryLabel));
    expect(categories.has('Legitimate Mainstream')).toBe(true);
    expect(categories.has('Brand Impersonation')).toBe(true);
    expect(categories.has('Known Threat Fixture')).toBe(true);
    expect(categories.has('Redirect Chain')).toBe(true);
    expect(categories.has('Input Resilience')).toBe(true);
    expect(categories.has('AI Engine Diagnostic')).toBe(true);
    expect(categories.has('Image Scam Diagnostic')).toBe(true);
    expect(categories.has('WhatsApp Bot Diagnostic')).toBe(true);
  });

  it('passes all 5 legitimate mainstream website tests (including LinkedIn) via Tranco Anchor validation', async () => {
    const legitCases = CONTROLLED_TEST_CASES.filter((tc) => tc.categoryLabel === 'Legitimate Mainstream');
    expect(legitCases).toHaveLength(5);

    for (const tc of legitCases) {
      const result = await TestRunner.runSingleTest(tc);
      expect(result.status).toBe('PASS');
      expect(result.actualVerdict?.severity).toBe('SAFE');
      expect(result.actualVerdict?.source).toBe('TRANCO_ANCHOR');
      expect(result.actualVerdict?.riskScore).toBe(0.0);
    }
  });

  it('passes all 3 synthetic brand-impersonation tests via heuristic detection', async () => {
    const impersonationCases = CONTROLLED_TEST_CASES.filter((tc) => tc.categoryLabel === 'Brand Impersonation');
    expect(impersonationCases).toHaveLength(3);

    for (const tc of impersonationCases) {
      const result = await TestRunner.runSingleTest(tc);
      expect(result.status).toBe('PASS');
      expect(result.actualVerdict?.severity).toBe('CRITICAL');
      expect(result.actualVerdict?.category).toBe('PHISHING');
      expect(result.actualVerdict?.source).toBe('HEURISTIC');
      expect(result.actualVerdict?.impersonatedBrand).toBeDefined();
    }
  });

  it('passes the verified offline malicious threat simulation fixture', async () => {
    const threatCase = CONTROLLED_TEST_CASES.find((tc) => tc.id === 'MALICIOUS_OFFLINE_KYC');
    expect(threatCase).toBeDefined();

    const result = await TestRunner.runSingleTest(threatCase!);
    expect(result.status).toBe('PASS');
    expect(result.actualVerdict?.severity).toBe('CRITICAL');
    expect(result.actualVerdict?.category).toBe('FAKE_KYC');
    expect(result.actualVerdict?.isBlocked).toBe(true);
    expect(result.actualVerdict?.source).toBe('OFFLINE_RULE');
  });

  it('passes the official Google Safe Browsing malware test fixture via path-specific threat matching', async () => {
    const malwareCase = CONTROLLED_TEST_CASES.find((tc) => tc.id === 'MALWARE_GOOGLE_TEST_URL');
    expect(malwareCase).toBeDefined();

    const result = await TestRunner.runSingleTest(malwareCase!);
    expect(result.status).toBe('PASS');
    expect(result.actualVerdict?.severity).toBe('CRITICAL');
    expect(result.actualVerdict?.category).toBe('MALWARE');
    expect(result.actualVerdict?.isBlocked).toBe(true);
    expect(result.actualVerdict?.source).toBe('OFFLINE_RULE');
    expect(result.actualVerdict?.matchedPattern).toBe('testsafebrowsing.appspot.com/s/malware.html');
  });

  it('passes the parent root domain path-isolation test without flagging malware', async () => {
    const cleanPathCase = CONTROLLED_TEST_CASES.find((tc) => tc.id === 'CLEAN_DOMAIN_CLEAN_PATH');
    expect(cleanPathCase).toBeDefined();

    const result = await TestRunner.runSingleTest(cleanPathCase!);
    expect(result.status).toBe('PASS');
    expect(result.actualVerdict?.category).not.toBe('MALWARE');
    expect(result.actualVerdict?.isBlocked).toBe(false);
  });

  it('passes the simulated multi-hop deceptive redirect chain test', async () => {
    const redirectCase = CONTROLLED_TEST_CASES.find((tc) => tc.id === 'SIMULATED_REDIRECT_CHAIN');
    expect(redirectCase).toBeDefined();

    const result = await TestRunner.runSingleTest(redirectCase!);
    expect(result.status).toBe('PASS');
    expect(result.actualRedirectChain).toBeDefined();
    expect(result.actualRedirectChain?.hops.length).toBe(3);
    expect(result.actualRedirectChain?.hasSuspiciousHop).toBe(true);
    expect(result.actualVerdict?.isBlocked).toBe(true);
  });

  it('passes the malformed input resilience test without throwing', async () => {
    const invalidCase = CONTROLLED_TEST_CASES.find((tc) => tc.id === 'INVALID_URL_SAFETY');
    expect(invalidCase).toBeDefined();

    const result = await TestRunner.runSingleTest(invalidCase!);
    expect(result.status).toBe('PASS');
    expect(result.actualVerdict).toBeDefined();
    expect(result.actualVerdict?.severity).toBe('SAFE');
  });

  it('passes all 4 AI Engine diagnostic test cases', async () => {
    const aiCases = CONTROLLED_TEST_CASES.filter((tc) => tc.categoryLabel === 'AI Engine Diagnostic');
    expect(aiCases).toHaveLength(4);

    for (const tc of aiCases) {
      const result = await TestRunner.runSingleTest(tc);
      expect(result.status).toBe('PASS');
      expect(result.notes.length).toBeGreaterThan(0);
    }
  });

  it('passes both Image Scam Diagnostic test cases (fake KYC OCR and fraudulent UPI)', async () => {
    const imageCases = CONTROLLED_TEST_CASES.filter((tc) => tc.categoryLabel === 'Image Scam Diagnostic');
    expect(imageCases).toHaveLength(2);

    for (const tc of imageCases) {
      const result = await TestRunner.runSingleTest(tc);
      expect(result.status).toBe('PASS');
      expect(result.actualVerdict?.severity).toMatch(/CRITICAL|HIGH/);
      expect(result.actualVerdict?.category).toMatch(/FAKE_KYC|UPI_FRAUD/);
      expect(result.notes.length).toBeGreaterThan(0);
    }
  });

  it('passes WhatsApp Bot inbound threat detection and consent diagnostic test case', async () => {
    const waCase = CONTROLLED_TEST_CASES.find((tc) => tc.id === 'WHATSAPP_BOT_DEMO_PIPELINE');
    expect(waCase).toBeDefined();

    const result = await TestRunner.runSingleTest(waCase!);
    expect(result.status).toBe('PASS');
    expect(result.actualVerdict?.severity).toBe('CRITICAL');
    expect(result.actualVerdict?.category).toBe('FAKE_KYC');
    expect(result.notes.some((n) => n.includes('Extracted'))).toBe(true);
    expect(result.notes.some((n) => n.includes('URL scan result'))).toBe(true);
  });

  it('executes runAllTests sequentially with progress tracking and achieves 100% pass rate', async () => {
    const progressUpdates: number[] = [];

    const allResults = await TestRunner.runAllTests(CONTROLLED_TEST_CASES, (completed, total) => {
      progressUpdates.push(completed);
      expect(total).toBe(20);
    });

    expect(allResults).toHaveLength(20);
    expect(progressUpdates).toHaveLength(20);

    const passedCount = allResults.filter((r) => r.status === 'PASS').length;
    expect(passedCount).toBe(20); // All 20 tests must pass
  });
});
