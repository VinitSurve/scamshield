import { describe, it, expect, vi, beforeEach } from 'vitest';
import { ApiClient } from '../src/services/api-client';

describe('ApiClient & Threat Intelligence Integration', () => {
  let client: ApiClient;

  beforeEach(() => {
    client = new ApiClient('https://api.scamshield.org', 2000);
  });

  it('performs k-anonymity 32-bit prefix lookup successfully', async () => {
    const res = await client.getPrefixMatches('3a7f82b1');
    expect(res).not.toBeNull();
    expect(res?.prefix).toBe('3a7f82b1');
    expect(Array.isArray(res?.matches)).toBe(true);
  });

  it('rejects invalid prefix format prior to network transmission', async () => {
    // Only 4 hex chars instead of 8
    const res = await client.getPrefixMatches('1234');
    expect(res).toBeNull();
  });

  it('submits community threat report with proper headers and payload', async () => {
    const res = await client.submitReport({
      indicator_type: 'DOMAIN',
      indicator_value: 'phishing-test-site.top',
      threat_category: 'PHISHING',
      description: 'Test report submission',
    });

    expect(res).not.toBeNull();
    expect(res?.status).toBe('RECORDED');
    expect(res?.report_id).toBe('test_rep_123');
  });

  it('handles offline / network abort without throwing unhandled exceptions', async () => {
    // Temporarily simulate network failure
    const originalFetch = globalThis.fetch;
    (globalThis as any).fetch = vi.fn(async () => {
      throw new Error('Network offline / connection refused');
    });

    const res = await client.getPrefixMatches('3a7f82b1');
    expect(res).toBeNull();

    // Verify structured response distinguishes offline from clean
    const detailed = await client.getPrefixLookup('3a7f82b1');
    expect(detailed.success).toBe(false);
    expect(detailed.isOffline).toBe(true);
    expect(detailed.status).toBe(0);
    expect(detailed.error).toContain('Network offline');

    // Restore fetch mock
    (globalThis as any).fetch = originalFetch;
  });

  it('provides structured ApiResponse with timeout indicator when request aborts', async () => {
    const originalFetch = globalThis.fetch;
    (globalThis as any).fetch = vi.fn(async () => {
      const abortErr = new Error('The operation was aborted');
      abortErr.name = 'AbortError';
      throw abortErr;
    });

    const detailed = await client.getPrefixLookup('3a7f82b1');
    expect(detailed.success).toBe(false);
    expect(detailed.isTimeout).toBe(true);
    expect(detailed.status).toBe(0);
    expect(detailed.error).toContain('timed out');

    (globalThis as any).fetch = originalFetch;
  });
});
