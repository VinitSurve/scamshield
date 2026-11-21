import { describe, it, expect, beforeEach, vi } from 'vitest';
import { ProviderRouter } from '../src/ai/provider-router';
import { KeyManager } from '../src/ai/key-manager';

describe('AI Provider Router & Fallback Coordinator', () => {
  beforeEach(async () => {
    await KeyManager.clearAllKeys();
    await ProviderRouter.updateSettings({
      enabled: true,
      primaryProvider: 'gemini',
      fallbackEnabled: true,
      keyRotationEnabled: true,
    });
  });

  it('determines execution order based on primary provider and fallback settings', async () => {
    const order1 = await ProviderRouter.getProviderExecutionOrder();
    expect(order1).toEqual(['gemini', 'groq']);

    await ProviderRouter.updateSettings({ primaryProvider: 'groq' });
    const order2 = await ProviderRouter.getProviderExecutionOrder();
    expect(order2).toEqual(['groq', 'gemini']);

    await ProviderRouter.updateSettings({ fallbackEnabled: false });
    const order3 = await ProviderRouter.getProviderExecutionOrder();
    expect(order3).toEqual(['groq']);
  });

  it('successfully executes request through primary provider when healthy key exists', async () => {
    await KeyManager.addKey('gemini', 'AIzaSyMockKeyForPrimaryTest', 'Gemini Primary');

    const result = await ProviderRouter.executeWithFallback('test prompt');

    expect(result.providerUsed).toBe('gemini');
    expect(result.fallbackOccurred).toBe(false);
    expect(result.rawOutput).toBeDefined();
    expect(result.latencyMs).toBeGreaterThanOrEqual(0);
  });

  it('falls back to secondary provider (Groq) when primary has no available keys', async () => {
    // Only configure Groq key, leave Gemini empty
    await KeyManager.addKey('groq', 'gsk_MockGroqKeyForFallback', 'Groq Backup');

    const result = await ProviderRouter.executeWithFallback('test prompt');

    expect(result.providerUsed).toBe('groq');
    expect(result.fallbackOccurred).toBe(true);
  });

  it('falls back to next key within same provider on rate limit (429)', async () => {
    const k1 = await KeyManager.addKey('gemini', 'AIzaSyKeyRateLimited', 'Gemini K1');
    const k2 = await KeyManager.addKey('gemini', 'AIzaSyKeyWorking', 'Gemini K2');

    // Spy on fetch: fail on first key with 429, succeed on second key
    const originalFetch = globalThis.fetch;
    let callCount = 0;

    globalThis.fetch = vi.fn(async (url: any, opts: any) => {
      callCount++;
      if (callCount === 1) {
        return {
          ok: false,
          status: 429,
          json: async () => ({
            error: {
              code: 429,
              message: 'Resource exhausted: rate limit exceeded',
              status: 'RESOURCE_EXHAUSTED',
            },
          }),
        } as any;
      }
      return originalFetch(url, opts);
    });

    try {
      const result = await ProviderRouter.executeWithFallback('test prompt');
      expect(result.providerUsed).toBe('gemini');

      const maskedKeys = await KeyManager.getMaskedKeys('gemini');
      const key1 = maskedKeys.find((k) => k.id === k1.id);
      const key2 = maskedKeys.find((k) => k.id === k2.id);

      expect(key1?.status).toBe('cooling_down');
      expect(key2?.status).toBe('healthy');
      expect(key2?.usageCount).toBe(1);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('throws informative error when all providers are exhausted', async () => {
    // No keys configured at all
    await expect(ProviderRouter.executeWithFallback('test prompt')).rejects.toThrow(
      /All AI providers and keys exhausted/
    );
  });
});
