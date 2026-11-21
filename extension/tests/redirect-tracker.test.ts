import { describe, it, expect, beforeEach } from 'vitest';
import { RedirectTracker } from '../src/background/redirect-tracker';

describe('Redirect Tracker & Multi-Hop Chain Monitoring', () => {
  const TAB_ID = 42;

  beforeEach(() => {
    RedirectTracker.removeChain(TAB_ID);
  });

  it('records navigation initiation with initial hop', () => {
    const chain = RedirectTracker.recordNavigationStart(TAB_ID, 'https://bit.ly/sbi-notice');

    expect(chain.tabId).toBe(TAB_ID);
    expect(chain.hops).toHaveLength(1);
    expect(chain.originalDomain).toBe('bit.ly');
    expect(chain.isCrossDomain).toBe(false);
  });

  it('detects cross-domain hops during URL redirection jumps', () => {
    RedirectTracker.recordNavigationStart(TAB_ID, 'https://bit.ly/sbi-notice');
    const updated = RedirectTracker.recordHop(TAB_ID, 'https://tracking.affiliate-network.example/click?id=1');

    expect(updated.hops).toHaveLength(2);
    expect(updated.isCrossDomain).toBe(true);
    expect(updated.hops[1].domain).toBe('tracking.affiliate-network.example');
  });

  it('flags hops leading to verified offline threat domains', () => {
    RedirectTracker.recordNavigationStart(TAB_ID, 'https://short.io/link');
    const updated = RedirectTracker.recordHop(TAB_ID, 'https://sbi-online-kyc-verification.top/');

    expect(updated.hops).toHaveLength(2);
    expect(updated.hasSuspiciousHop).toBe(true);
    expect(updated.hops[1].isSuspicious).toBe(true);
    expect(updated.hops[1].reason).toContain('verified threat');
  });

  it('detects redirect loops exceeding maximum allowed hops (>5)', () => {
    RedirectTracker.recordNavigationStart(TAB_ID, 'https://hop1.example');
    RedirectTracker.recordHop(TAB_ID, 'https://hop2.example');
    RedirectTracker.recordHop(TAB_ID, 'https://hop3.example');
    RedirectTracker.recordHop(TAB_ID, 'https://hop4.example');
    RedirectTracker.recordHop(TAB_ID, 'https://hop5.example');
    const loopChain = RedirectTracker.recordHop(TAB_ID, 'https://hop6.example');

    expect(loopChain.hops.length).toBeGreaterThanOrEqual(5);
    expect(loopChain.hasSuspiciousHop).toBe(true);
  });
});
