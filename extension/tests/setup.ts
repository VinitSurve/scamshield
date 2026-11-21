/**
 * Chrome Extension API Mock for Vitest
 */
import { vi } from 'vitest';

const storageMock: Record<string, unknown> = {};

export const chromeMock = {
  runtime: {
    id: 'scamshield-extension-test-id',
    lastError: null as { message?: string } | null,
    getURL: (path: string) => `chrome-extension://scamshield-extension-test-id/${path}`,
    sendMessage: vi.fn((_message, callback) => {
      if (callback) callback({ success: true });
    }),
    onMessage: {
      addListener: vi.fn(),
      removeListener: vi.fn(),
    },
    onInstalled: {
      addListener: vi.fn(),
    },
    onStartup: {
      addListener: vi.fn(),
    },
    openOptionsPage: vi.fn(),
  },
  storage: {
    local: {
      get: vi.fn(async (keys) => {
        if (!keys) return { ...storageMock };
        if (typeof keys === 'string') return { [keys]: storageMock[keys] };
        if (Array.isArray(keys)) {
          const res: Record<string, unknown> = {};
          keys.forEach((k) => {
            if (storageMock[k] !== undefined) res[k] = storageMock[k];
          });
          return res;
        }
        return {};
      }),
      set: vi.fn(async (items) => {
        Object.assign(storageMock, items);
      }),
      remove: vi.fn(async (keys) => {
        const arr = Array.isArray(keys) ? keys : [keys];
        arr.forEach((k) => delete storageMock[k]);
      }),
      clear: vi.fn(async () => {
        for (const k in storageMock) delete storageMock[k];
      }),
    },
  },
  tabs: {
    query: vi.fn(async () => [{ id: 1, url: 'https://example.com' }]),
    update: vi.fn(async (tabId, props) => ({ id: tabId, ...props })),
    onRemoved: {
      addListener: vi.fn(),
    },
  },
  webNavigation: {
    onBeforeNavigate: {
      addListener: vi.fn(),
    },
    onCommitted: {
      addListener: vi.fn(),
    },
  },
  action: {
    setBadgeText: vi.fn(),
    setBadgeBackgroundColor: vi.fn(),
    setTitle: vi.fn(),
  },
  declarativeNetRequest: {
    getDynamicRules: vi.fn(async () => []),
    updateDynamicRules: vi.fn(async () => {}),
  },
};

// Install global chrome mock
(globalThis as any).chrome = chromeMock;

// Install mock fetch so unit tests execute deterministically with 0ms latency
(globalThis as any).fetch = vi.fn(async (url: string | URL | Request) => {
  const urlStr = typeof url === 'string' ? url : url.toString();
  if (urlStr.includes('/api/v1/reputation/prefix/')) {
    return {
      ok: true,
      status: 200,
      json: async () => ({ prefix: urlStr.split('/').pop(), matches: [] }),
    };
  }
  if (urlStr.includes('/api/v1/reports')) {
    return {
      ok: true,
      status: 201,
      json: async () => ({ report_id: 'test_rep_123', status: 'RECORDED' }),
    };
  }
  if (urlStr.includes('generativelanguage.googleapis.com')) {
    return {
      ok: true,
      status: 200,
      json: async () => ({
        candidates: [
          {
            content: {
              parts: [
                {
                  text: JSON.stringify({
                    classification: 'SCAM',
                    riskLevel: 'HIGH',
                    confidenceScore: 0.92,
                    scamCategory: 'BANKING_KYC_PHISHING',
                    summary: 'Impersonates bank with false urgency to extract credentials.',
                    socialEngineeringTactics: ['Urgency', 'Fear'],
                    indicators: [
                      {
                        type: 'SUSPICIOUS_URL',
                        description: 'Directs user to unofficial domain',
                        severity: 'HIGH',
                      },
                    ],
                    extractedEntities: {
                      brandImpersonated: 'SBI',
                      suspiciousUrls: ['http://sbi-kyc-update.top'],
                    },
                    recommendedActions: ['Do not click the link.', 'Do not share OTP.'],
                    explanation: 'Verified banking impersonation pattern.',
                  }),
                },
              ],
            },
          },
        ],
      }),
    };
  }
  if (urlStr.includes('api.groq.com')) {
    return {
      ok: true,
      status: 200,
      json: async () => ({
        choices: [
          {
            message: {
              content: JSON.stringify({
                classification: 'SCAM',
                riskLevel: 'HIGH',
                confidenceScore: 0.88,
                scamCategory: 'BANKING_KYC_PHISHING',
                summary: 'Groq detection: Urgency scam impersonating bank.',
                socialEngineeringTactics: ['Urgency'],
                indicators: [
                  {
                    type: 'SUSPICIOUS_URL',
                    description: 'Directs to unofficial domain',
                    severity: 'HIGH',
                  },
                ],
                extractedEntities: { brandImpersonated: 'SBI' },
                recommendedActions: ['Ignore the message.'],
                explanation: 'Groq inference identifies scam pattern.',
              }),
            },
          },
        ],
      }),
    };
  }
  return {
    ok: true,
    status: 200,
    json: async () => ({}),
  };
});

