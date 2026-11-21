import { describe, it, expect, beforeEach } from 'vitest';
import { KeyManager } from '../src/ai/key-manager';

describe('AI Key Manager & Health Pool', () => {
  beforeEach(async () => {
    await KeyManager.clearAllKeys();
  });

  it('supports adding multiple keys for Gemini and Groq independently', async () => {
    const k1 = await KeyManager.addKey('gemini', 'AIzaSyGeminiAlpha1234567890', 'Gemini Key 1');
    const k2 = await KeyManager.addKey('gemini', 'AIzaSyGeminiBeta1234567890', 'Gemini Key 2');
    const g1 = await KeyManager.addKey('groq', 'gsk_GroqAlpha12345678901234567890', 'Groq Key 1');

    expect(k1.maskedKey).toContain('••••••••');
    expect(k1.maskedKey.startsWith('AIza')).toBe(true);
    expect(k2.maskedKey.startsWith('AIza')).toBe(true);
    expect(g1.maskedKey.startsWith('gsk_')).toBe(true);

    const geminiKeys = await KeyManager.getMaskedKeys('gemini');
    const groqKeys = await KeyManager.getMaskedKeys('groq');

    expect(geminiKeys.length).toBe(2);
    expect(groqKeys.length).toBe(1);
  });

  it('rotates through healthy keys in round-robin fashion', async () => {
    await KeyManager.addKey('gemini', 'AIzaSyTestKeyOne1234567890', 'Key A');
    await KeyManager.addKey('gemini', 'AIzaSyTestKeyTwo1234567890', 'Key B');

    const first = await KeyManager.getNextAvailableKey('gemini');
    const second = await KeyManager.getNextAvailableKey('gemini');
    const third = await KeyManager.getNextAvailableKey('gemini');

    expect(first?.label).toBe('Key A');
    expect(second?.label).toBe('Key B');
    expect(third?.label).toBe('Key A'); // Wraps around
  });

  it('skips disabled and invalid keys', async () => {
    const k1 = await KeyManager.addKey('gemini', 'AIzaSyKeyA1234567890', 'Key A');
    const k2 = await KeyManager.addKey('gemini', 'AIzaSyKeyB1234567890', 'Key B');

    // Disable Key A
    await KeyManager.toggleKey(k1.id, false);

    const selected1 = await KeyManager.getNextAvailableKey('gemini');
    const selected2 = await KeyManager.getNextAvailableKey('gemini');

    expect(selected1?.id).toBe(k2.id);
    expect(selected2?.id).toBe(k2.id);

    // Mark Key B invalid
    await KeyManager.recordAuthFailure(k2.id, 'Invalid key');
    const selectedNone = await KeyManager.getNextAvailableKey('gemini');
    expect(selectedNone).toBeNull();
  });

  it('enters cooling_down state on HTTP 429 and skips cooling keys', async () => {
    const k1 = await KeyManager.addKey('gemini', 'AIzaSyCoolingTest123456', 'Key 1');
    const k2 = await KeyManager.addKey('gemini', 'AIzaSyActiveTest123456', 'Key 2');

    // Trigger rate limit on Key 1 with 60s cooldown
    await KeyManager.recordRateLimit(k1.id, 60);

    const masked = await KeyManager.getMaskedKeys('gemini');
    const key1Masked = masked.find((k) => k.id === k1.id);

    expect(key1Masked?.status).toBe('cooling_down');
    expect(key1Masked?.cooldownRemainingSeconds).toBeGreaterThan(0);
    expect(key1Masked?.rateLimitCount).toBe(1);

    // Key selector must immediately skip Key 1 and pick Key 2
    const selected = await KeyManager.getNextAvailableKey('gemini');
    expect(selected?.id).toBe(k2.id);
  });

  it('tracks usage and success counts accurately', async () => {
    const k = await KeyManager.addKey('groq', 'gsk_TestTrackUsage1234567890', 'Groq Key');
    await KeyManager.recordSuccess(k.id);
    await KeyManager.recordSuccess(k.id);

    const masked = await KeyManager.getMaskedKeys('groq');
    const keyConfig = masked.find((m) => m.id === k.id);

    expect(keyConfig?.usageCount).toBe(2);
    expect(keyConfig?.status).toBe('healthy');
  });

  it('generates accurate provider health statistics', async () => {
    await KeyManager.addKey('gemini', 'AIzaSyHealthyKey12345', 'Gemini 1');
    const k2 = await KeyManager.addKey('gemini', 'AIzaSyCoolingKey12345', 'Gemini 2');
    await KeyManager.recordRateLimit(k2.id, 30);

    const stats = await KeyManager.getHealthStats();

    expect(stats.gemini.totalKeys).toBe(2);
    expect(stats.gemini.healthyKeys).toBe(1);
    expect(stats.gemini.coolingDownKeys).toBe(1);
    expect(stats.gemini.status).toBe('degraded');
    expect(stats.groq.status).toBe('unconfigured');
  });

  it('never leaks raw API keys when returning masked representations', async () => {
    const secret = 'AIzaSySecretSuperPrivateToken99999';
    await KeyManager.addKey('gemini', secret, 'Sensitive');

    const maskedList = await KeyManager.getMaskedKeys();
    for (const m of maskedList) {
      expect(m.maskedKey).not.toBe(secret);
      expect(m.maskedKey).toContain('••••••••');
      expect((m as any).key).toBeUndefined();
    }
  });
});
