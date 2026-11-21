import { describe, it, expect, beforeEach } from 'vitest';
import { AIService } from '../src/ai/ai-service';
import { KeyManager } from '../src/ai/key-manager';
import { PiiScrubber } from '../src/ai/pii-scrubber';

describe('ScamShield AI Service Master Pipeline', () => {
  beforeEach(async () => {
    await KeyManager.clearAllKeys();
    await AIService.updateSettings({
      enabled: true,
      primaryProvider: 'gemini',
      fallbackEnabled: true,
    });
  });

  describe('Privacy & PII Sanitizer', () => {
    it('redacts Indian and international phone numbers from text', () => {
      const raw = 'Please call officer immediately at +91 9876543210 or 9876543210.';
      const scrubbed = PiiScrubber.sanitizeText(raw);
      expect(scrubbed).not.toContain('9876543210');
      expect(scrubbed).toContain('[PHONE_NUMBER_REDACTED]');
    });

    it('redacts OTP and verification codes while preserving intent', () => {
      const raw = 'Your one-time password OTP is 849201 for electricity bill payment.';
      const scrubbed = PiiScrubber.sanitizeText(raw);
      expect(scrubbed).not.toContain('849201');
      expect(scrubbed).toContain('[OTP_REDACTED]');
    });

    it('redacts personal email addresses and UPI handles', () => {
      const raw = 'Send funds to victim.user@okhdfcbank or email admin@scamsite.org';
      const scrubbed = PiiScrubber.sanitizeText(raw);
      expect(scrubbed).not.toContain('victim.user@okhdfcbank');
      expect(scrubbed).toContain('[UPI_HANDLE_REDACTED]');
    });

    it('sanitizes sensitive auth and token parameters from URLs', () => {
      const raw = 'https://fake-bank.example/login?token=secret_auth_token_999&user_id=12345';
      const clean = PiiScrubber.sanitizeUrl(raw);
      expect(clean).not.toContain('secret_auth_token_999');
      expect(clean).toContain('token=%5BREDACTED%5D');
    });
  });

  describe('Message Scam Analysis', () => {
    it('analyzes suspicious banking message and produces strict structured schema', async () => {
      await KeyManager.addKey('gemini', 'AIzaSyMockKeyForMessageAnalysis', 'Gemini Analysis');

      const result = await AIService.analyzeMessage({
        messageText:
          'Dear customer, your SBI account is blocked. Verify KYC at http://sbi-kyc-update.top to reactivate.',
        sourceType: 'SMS',
        userLanguage: 'en',
      });

      expect(result.success).toBe(true);
      expect(result.classification).toBe('SCAM');
      expect(result.riskLevel).toBe('HIGH');
      expect(result.scamCategory).toBe('BANKING_KYC_PHISHING');
      expect(result.summary).toBeDefined();
      expect(result.indicators.length).toBeGreaterThan(0);
      expect(result.recommendedActions.length).toBeGreaterThan(0);
      expect(result.providerUsed).toBe('gemini');
    });

    it('handles empty message input gracefully without calling LLM', async () => {
      const result = await AIService.analyzeMessage({ messageText: '   ' });
      expect(result.success).toBe(false);
      expect(result.classification).toBe('UNKNOWN');
      expect(result.summary).toContain('No text provided');
    });

    it('returns robust heuristic fallback response with scam indicators when no operational AI keys are available', async () => {
      // Zero AI keys configured: must fall back to local heuristics and NOT return UNKNOWN 0%
      const result = await AIService.analyzeMessage({
        messageText: 'Claim your lottery bonus of Rs 50000 now: http://lottery.example',
      });

      expect(result.success).toBe(true);
      expect(result.aiStatus).toBe('FAILED');
      expect(result.securityStatus).toBe('SUCCESS');
      expect(result.isLocalHeuristicFallback).toBe(true);
      expect(result.classification).toBe('SCAM');
      expect(result.confidenceScore).toBeGreaterThan(0.7);
      expect(result.recommendedActions.length).toBeGreaterThan(0);
      expect(result.summary).toContain('AI ANALYSIS UNAVAILABLE');
      expect(result.summary).toContain('local security checks detected');
    });
  });

  describe('Website Threat Evidence Explanation', () => {
    it('explains deterministic scanner signals without hallucinating external feeds', async () => {
      await KeyManager.addKey('gemini', 'AIzaSyMockKeyForExplanation', 'Gemini Explainer');

      const explanation = await AIService.explainUrlThreat({
        url: 'https://sbi-online-kyc-verification.example/login',
        domain: 'sbi-online-kyc-verification.example',
        verdictSeverity: 'HIGH',
        riskScore: 85,
        evidence: [
          'Brand impersonation: State Bank of India',
          'Punycode homoglyph detected',
          'Password input detected on unrated domain',
        ],
        redirectHops: 3,
        userLanguage: 'en',
      });

      expect(explanation.success).toBe(true);
      expect(explanation.summary).toBeDefined();
      expect(explanation.safetyGuidance.length).toBeGreaterThan(0);
    });
  });

  describe('Key Validation Testing', () => {
    it('validates a configured key by ID', async () => {
      const key = await KeyManager.addKey('gemini', 'AIzaSyKeyToValidate', 'Validation Test');
      const testResult = await AIService.testKeyById(key.id);

      expect(testResult.valid).toBe(true);
      expect(testResult.statusCode).toBe(200);
      expect(testResult.sanitizedMessage).toContain('verified');
    });
  });
});
