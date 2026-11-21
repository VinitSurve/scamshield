import { describe, it, expect, beforeEach, afterEach, beforeAll, afterAll, vi } from 'vitest';
import http from 'http';
import { app, processedMessageIds, clearProcessedMessageIds } from '../src/webhook';
import { providerManager } from '../src/provider-state';
import { whatsAppClient, WhatsAppClient } from '../src/whatsapp-client';
import { config } from '../src/config';

describe('WhatsApp Provider State & Meta Error 131031 Resilience Suite', () => {
  let server: http.Server;
  let baseUrl: string;

  beforeAll(async () => {
    await new Promise<void>((resolve) => {
      server = http.createServer(app);
      server.listen(0, '127.0.0.1', () => {
        const addr = server.address() as { port: number };
        baseUrl = `http://127.0.0.1:${addr.port}`;
        resolve();
      });
    });
  });

  afterAll(async () => {
    await new Promise<void>((resolve) => {
      server.close(() => resolve());
    });
  });

  beforeEach(() => {
    providerManager.reset();
    clearProcessedMessageIds();
    whatsAppClient.resetFetchFn();
  });

  afterEach(() => {
    providerManager.reset();
    whatsAppClient.resetFetchFn();
  });

  describe('Provider State Manager Unit Tests', () => {
    it('initializes with clean HEALTHY status and empty error state', () => {
      const summary = providerManager.getStatusSummary('cloud_api');
      expect(summary.status).toBe('HEALTHY');
      expect(summary.isBlocked).toBe(false);
      expect(summary.lockDetails.isLocked).toBe(false);
      expect(summary.lockDetails.code).toBeNull();
      expect(summary.lastError).toBeNull();
      expect(summary.stats.totalReceived).toBe(0);
      expect(summary.stats.totalSent).toBe(0);
      expect(summary.stats.totalBlockedDrops).toBe(0);
    });

    it('correctly reports MOCK_MODE when running in mock or demo mode', () => {
      expect(providerManager.getStatus('mock')).toBe('MOCK_MODE');
      expect(providerManager.getStatus('demo')).toBe('MOCK_MODE');
      expect(providerManager.getStatus('cloud_api')).toBe('HEALTHY');
    });

    it('marks provider as BLOCKED when Meta account lock error 131031 is recorded', () => {
      providerManager.markBlocked(131031, 'WhatsApp Business Account Locked by Meta (Error 131031)');
      expect(providerManager.getIsBlocked()).toBe(true);
      expect(providerManager.getBlockCode()).toBe(131031);
      expect(providerManager.getBlockReason()).toContain('Error 131031');
      expect(providerManager.getStatus('cloud_api')).toBe('BLOCKED');
      expect(providerManager.getStatus('mock')).toBe('BLOCKED');

      const summary = providerManager.getStatusSummary('cloud_api');
      expect(summary.lockDetails.isLocked).toBe(true);
      expect(summary.lockDetails.code).toBe(131031);
      expect(summary.lastError?.code).toBe(131031);
      expect(summary.lastError?.transient).toBe(false);
    });

    it('resets state completely on administrative reset', () => {
      providerManager.markBlocked(131031, 'Locked');
      expect(providerManager.getIsBlocked()).toBe(true);

      providerManager.reset();
      expect(providerManager.getIsBlocked()).toBe(false);
      expect(providerManager.getStatus('cloud_api')).toBe('HEALTHY');
      expect(providerManager.getBlockReason()).toBeNull();
    });
  });

  describe('Error Classification Logic', () => {
    it('correctly identifies Error 131031 and permanent locks', () => {
      expect(WhatsAppClient.isPermanentError(131031)).toBe(true);
      expect(WhatsAppClient.isPermanentError(131030)).toBe(true);
      expect(WhatsAppClient.isPermanentError(190)).toBe(true);
      expect(WhatsAppClient.isPermanentError(100)).toBe(true);
      expect(WhatsAppClient.isPermanentError(undefined, 'Business account has been locked.')).toBe(true);
      expect(WhatsAppClient.isPermanentError(undefined, 'Account has been locked by Meta.')).toBe(true);
    });

    it('correctly differentiates transient errors (429, 500, 130429, 131000)', () => {
      expect(WhatsAppClient.isTransientError(429)).toBe(true);
      expect(WhatsAppClient.isTransientError(500)).toBe(true);
      expect(WhatsAppClient.isTransientError(502)).toBe(true);
      expect(WhatsAppClient.isTransientError(503)).toBe(true);
      expect(WhatsAppClient.isTransientError(200, 130429)).toBe(true);
      expect(WhatsAppClient.isTransientError(200, 131000)).toBe(true);

      expect(WhatsAppClient.isTransientError(400)).toBe(false);
      expect(WhatsAppClient.isTransientError(401)).toBe(false);
      expect(WhatsAppClient.isTransientError(404)).toBe(false);
    });
  });

  describe('Meta Error 131031 Immediate Circuit Breaker (Zero Retry)', () => {
    it('halts immediately on Error 131031 without executing retries and sets BLOCKED', async () => {
      let callCount = 0;
      const mockFetch = vi.fn().mockImplementation(async () => {
        callCount++;
        return {
          ok: false,
          status: 400,
          text: async () =>
            JSON.stringify({
              error: {
                message: 'Business account has been locked.',
                type: 'OAuthException',
                code: 131031,
                error_subcode: 2494056,
              },
            }),
        };
      });

      const originalMode = config.mode;
      const originalToken = config.accessToken;
      const originalPhoneId = config.phoneNumberId;

      config.mode = 'cloud_api';
      config.accessToken = 'test_token';
      config.phoneNumberId = 'test_phone_id';
      whatsAppClient.setFetchFn(mockFetch as unknown as typeof fetch);

      try {
        const result = await whatsAppClient.sendMessage('+919876543210', 'Test message', {
          maxRetries: 3,
          baseDelayMs: 10,
        });

        // 1. Must fail with BLOCKED status
        expect(result.status).toBe('BLOCKED');
        expect(result.success).toBe(false);
        expect(result.errorCode).toBe(131031);
        expect(result.error).toContain('Business account has been locked');

        // 2. ZERO RETRIES - exactly 1 call was made to Meta
        expect(callCount).toBe(1);

        // 3. Provider state must now be BLOCKED
        expect(providerManager.getIsBlocked()).toBe(true);
        expect(providerManager.getBlockCode()).toBe(131031);
        expect(providerManager.getStatus('cloud_api')).toBe('BLOCKED');

        // 4. Subsequent calls while BLOCKED must NOT call Meta at all (0 new calls)
        const secondResult = await whatsAppClient.sendMessage('+919876543210', 'Second attempt');
        expect(secondResult.status).toBe('BLOCKED');
        expect(secondResult.attempts).toBe(0);
        expect(callCount).toBe(1); // Still 1! No second fetch attempt made

        const summary = providerManager.getStatusSummary('cloud_api');
        expect(summary.stats.totalBlockedDrops).toBe(1);
      } finally {
        config.mode = originalMode;
        config.accessToken = originalToken;
        config.phoneNumberId = originalPhoneId;
      }
    });
  });

  describe('Transient Error Retry & Recovery', () => {
    it('retries transient 429 error and succeeds when subsequent attempt returns 200', async () => {
      let callCount = 0;
      const mockFetch = vi.fn().mockImplementation(async () => {
        callCount++;
        if (callCount === 1) {
          return {
            ok: false,
            status: 429,
            text: async () => JSON.stringify({ error: { message: 'Rate limit hit', code: 130429 } }),
          };
        }
        return {
          ok: true,
          status: 200,
          json: async () => ({ messages: [{ id: 'wamid.success123' }] }),
          text: async () => '',
        };
      });

      const originalMode = config.mode;
      const originalToken = config.accessToken;
      const originalPhoneId = config.phoneNumberId;

      config.mode = 'cloud_api';
      config.accessToken = 'test_token';
      config.phoneNumberId = 'test_phone_id';
      whatsAppClient.setFetchFn(mockFetch as unknown as typeof fetch);

      try {
        const result = await whatsAppClient.sendMessage('+919876543210', 'Recoverable alert', {
          maxRetries: 3,
          baseDelayMs: 10,
        });

        expect(result.status).toBe('DELIVERED');
        expect(result.success).toBe(true);
        expect(result.messageId).toBe('wamid.success123');
        expect(result.attempts).toBe(2);
        expect(callCount).toBe(2);
        expect(providerManager.getStatusSummary('cloud_api').stats.totalRetries).toBe(1);
      } finally {
        config.mode = originalMode;
        config.accessToken = originalToken;
        config.phoneNumberId = originalPhoneId;
      }
    });

    it('retries up to maxRetries on persistent 500 error then fails with FAILED status', async () => {
      let callCount = 0;
      const mockFetch = vi.fn().mockImplementation(async () => {
        callCount++;
        return {
          ok: false,
          status: 500,
          text: async () => JSON.stringify({ error: { message: 'Meta internal server error', code: 131000 } }),
        };
      });

      const originalMode = config.mode;
      const originalToken = config.accessToken;
      const originalPhoneId = config.phoneNumberId;

      config.mode = 'cloud_api';
      config.accessToken = 'test_token';
      config.phoneNumberId = 'test_phone_id';
      whatsAppClient.setFetchFn(mockFetch as unknown as typeof fetch);

      try {
        const result = await whatsAppClient.sendMessage('+919876543210', 'Persistent 500 alert', {
          maxRetries: 3,
          baseDelayMs: 10,
        });

        expect(result.status).toBe('FAILED');
        expect(result.success).toBe(false);
        expect(result.attempts).toBe(3);
        expect(callCount).toBe(3);
        // Provider is DEGRADED, not permanently locked
        expect(providerManager.getIsBlocked()).toBe(false);
      } finally {
        config.mode = originalMode;
        config.accessToken = originalToken;
        config.phoneNumberId = originalPhoneId;
      }
    });
  });

  describe('Mock / Demo Mode Simulation (Safe Offline Operation)', () => {
    it('delivers simulated responses with explicit isSimulated: true without calling Meta API', async () => {
      const mockFetch = vi.fn();
      whatsAppClient.setFetchFn(mockFetch as unknown as typeof fetch);

      const result = await whatsAppClient.sendMessage('+919876543210', 'Demo message', {
        forceSimulate: true,
      });

      expect(result.success).toBe(true);
      expect(result.isSimulated).toBe(true);
      expect(result.status).toBe('SIMULATED_SUCCESS');
      expect(result.messageId).toContain('mock-msg-');
      expect(mockFetch).not.toHaveBeenCalled();

      const summary = providerManager.getStatusSummary('mock');
      expect(summary.stats.totalSimulated).toBe(1);
    });
  });

  describe('Webhook Endpoints & Deduplication', () => {
    it('GET /health reports providerStatus and lock state', async () => {
      const res = await fetch(`${baseUrl}/health`);
      expect(res.status).toBe(200);
      const data = await res.json();
      expect(data.status).toBe('healthy');
      expect(data.providerStatus).toBeDefined();
      expect(data.isBlocked).toBe(false);
    });

    it('GET /api/v1/whatsapp/status provides comprehensive diagnostics', async () => {
      const res = await fetch(`${baseUrl}/api/v1/whatsapp/status`);
      expect(res.status).toBe(200);
      const data = await res.json();
      expect(data.status).toBeDefined();
      expect(data.lockDetails).toBeDefined();
      expect(data.stats).toBeDefined();
      expect(data.serverTime).toBeDefined();
    });

    it('POST /api/v1/whatsapp/reset-status resets blocked status', async () => {
      providerManager.markBlocked(131031, 'Test lock');
      expect(providerManager.getIsBlocked()).toBe(true);

      const res = await fetch(`${baseUrl}/api/v1/whatsapp/reset-status`, {
        method: 'POST',
      });
      expect(res.status).toBe(200);
      const data = await res.json();
      expect(data.success).toBe(true);
      expect(providerManager.getIsBlocked()).toBe(false);
    });

    it('POST /api/v1/whatsapp/simulate processes inbound text and returns complete trace', async () => {
      const res = await fetch(`${baseUrl}/api/v1/whatsapp/simulate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          from: '+919988776655',
          text: 'Urgent: SBI Account suspended due to KYC. Verify at https://sbi-fake-kyc.top',
        }),
      });

      expect(res.status).toBe(200);
      const data = await res.json();
      expect(data.sender).toBe('+919988776655');
      expect(data.type).toBe('text');
      expect(data.scanResult).toBeDefined();
      expect(data.scanResult.verdict).toMatch(/HIGH|CRITICAL/);
      expect(data.formattedReply).toContain('SCAMSHIELD THREAT ALERT');
      expect(data.deliveryResult).toBeDefined();
      expect(data.deliveryResult.isSimulated).toBe(true);
    }, 25000);

    it('POST /webhook rejects duplicate message IDs (webhook deduplication)', async () => {
      const payload = {
        object: 'whatsapp_business_account',
        entry: [
          {
            changes: [
              {
                value: {
                  messages: [
                    {
                      id: 'msg_unique_dedup_001',
                      from: '+919876543210',
                      type: 'text',
                      text: { body: 'Hello ScamShield' },
                    },
                  ],
                },
              },
            ],
          },
        ],
      };

      // First webhook receipt: succeeds and records message ID
      const res1 = await fetch(`${baseUrl}/webhook`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      expect(res1.status).toBe(200);
      const data1 = await res1.json();
      expect(data1.status).toBe('EVENT_RECEIVED');
      expect(processedMessageIds.has('msg_unique_dedup_001')).toBe(true);

      const initialReceivedCount = providerManager.getStatusSummary('cloud_api').stats.totalReceived;

      // Second webhook receipt with the SAME message ID: skipped by deduplication
      const res2 = await fetch(`${baseUrl}/webhook`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      expect(res2.status).toBe(200);
      // Inbound count should not increase because it was deduplicated
      expect(providerManager.getStatusSummary('cloud_api').stats.totalReceived).toBe(initialReceivedCount);
    });
  });
});
