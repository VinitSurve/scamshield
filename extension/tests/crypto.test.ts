import { describe, it, expect } from 'vitest';
import { sha256Hex, get32BitPrefix, generateRandomId } from '../src/utils/crypto';

describe('Crypto & Prefix Generator', () => {
  it('computes accurate SHA-256 hex string using Web Crypto', async () => {
    const hash = await sha256Hex('example.com');
    expect(hash).toHaveLength(64);
    expect(hash).toMatch(/^[0-9a-f]{64}$/);
    // Known SHA-256 for 'example.com'
    expect(hash).toBe('a379a6f6eeafb9a55e378c118034e2751e682fab9f2d30ab13d2125586ce1947');
  });

  it('extracts exactly 32-bit (8 hex chars) prefix for k-anonymity privacy lookups', () => {
    const hash = 'a379a6f6eeafb9a55e378c118034e2751e682fab9f2d30ab13d2125586ce1947';
    const prefix = get32BitPrefix(hash);
    expect(prefix).toBe('a379a6f6');
    expect(prefix).toHaveLength(8);
  });

  it('generates unique random IDs with custom prefixes', () => {
    const id1 = generateRandomId('report');
    const id2 = generateRandomId('report');
    expect(id1.startsWith('report_')).toBe(true);
    expect(id2.startsWith('report_')).toBe(true);
    expect(id1).not.toBe(id2);
  });
});
