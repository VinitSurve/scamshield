import { describe, it, expect, beforeEach } from 'vitest';
import { AIService } from '../src/ai/ai-service';
import { LocalMessageHeuristics } from '../src/security/local-message-heuristics';
import { KeyManager } from '../src/ai/key-manager';
import { ProviderRouter } from '../src/ai/provider-router';

describe('ScamShield SMS & WhatsApp AI Message Analyzer Engine', () => {
  beforeEach(async () => {
    await KeyManager.clearAllKeys();
    await ProviderRouter.updateSettings({
      enabled: true,
      primaryProvider: 'gemini',
      fallbackEnabled: true,
      keyRotationEnabled: true,
    });
  });

  describe('Local Heuristic Analysis Engine (Deterministic Safety Net)', () => {
    it('accurately identifies the real SBI KYC scam message with HIGH risk and full indicators', () => {
      const sbiMessage =
        'URGENT: Dear Customer, your SBI bank account will be blocked today due to incomplete KYC. Update immediately to avoid account suspension. Verify now: https://sbi-kyc-alert.example/verify Call customer care: +91 9876543210';

      const result = LocalMessageHeuristics.analyze(sbiMessage, 'SMS');

      expect(result.success).toBe(true);
      expect(result.classification).toBe('SCAM');
      expect(result.riskLevel).toBe('HIGH');
      expect(result.confidenceScore).toBeGreaterThanOrEqual(0.85); // 92%
      expect(result.scamCategory).toBe('BANKING_KYC_PHISHING');
      expect(result.extractedEntities.brandImpersonated).toBe('SBI');
      expect(result.extractedEntities.suspiciousUrls).toContain('https://sbi-kyc-alert.example/verify');

      // Check detected indicator types
      const indicatorTypes = result.indicators.map((i) => i.type);
      expect(indicatorTypes).toContain('BRAND_IMPERSONATION');
      expect(indicatorTypes).toContain('KYC_FRAUD_LURE');
      expect(indicatorTypes).toContain('COERCIVE_THREAT');
      expect(indicatorTypes).toContain('SUSPICIOUS_URL');
      expect(indicatorTypes).toContain('UNOFFICIAL_CONTACT');

      // Check tactics
      expect(result.socialEngineeringTactics).toContain('authority_impersonation');
      expect(result.socialEngineeringTactics).toContain('urgency');
      expect(result.socialEngineeringTactics).toContain('fear');

      // Verify explanation explicitly references local heuristics
      expect(result.summary).toContain('AI ANALYSIS UNAVAILABLE');
      expect(result.summary).toContain('SBI brand impersonation');
      expect(result.summary).toContain('KYC-related request');
      expect(result.isLocalHeuristicFallback).toBe(true);
    });

    it('correctly classifies legitimate shopping delivery messages as SAFE with LOW risk (False Positive Prevention)', () => {
      const legitMessage =
        'Your order has been shipped. You can track your delivery through the official shopping app. Expected delivery: 24 November. Thank you for shopping with us.';

      const result = LocalMessageHeuristics.analyze(legitMessage, 'SMS');

      expect(result.success).toBe(true);
      expect(result.classification).toBe('SAFE');
      expect(result.riskLevel).toBe('LOW');
      expect(result.confidenceScore).toBeLessThanOrEqual(0.1);
      expect(result.scamCategory).toBe('LEGITIMATE_COMMUNICATION');
      expect(result.indicators.length).toBe(0);
      expect(result.summary).toContain('no obvious phishing indicators');
    });

    it('detects electricity bill disconnection scam messages', () => {
      const elecMessage =
        'Dear consumer your electricity power will be disconnected tonight at 9:30 pm from electricity office because your previous month bill was not updated. Please immediately contact our officer at 9876543210.';

      const result = LocalMessageHeuristics.analyze(elecMessage, 'WHATSAPP');

      expect(result.classification).toBe('SCAM');
      expect(result.riskLevel).toBe('HIGH');
      expect(result.extractedEntities.brandImpersonated).toBe('Electricity Department');
      expect(result.indicators.map((i) => i.type)).toContain('COERCIVE_THREAT');
    });

    it('detects OTP and UPI PIN credential theft attempts with CRITICAL severity', () => {
      const otpMessage =
        'Dear customer, we detected an unauthorized transaction. Please share your OTP or UPI PIN immediately with customer support to block the payment.';

      const result = LocalMessageHeuristics.analyze(otpMessage, 'SMS');

      expect(result.classification).toBe('SCAM');
      expect(result.riskLevel).toBe('CRITICAL');
      expect(result.confidenceScore).toBeGreaterThanOrEqual(0.95);
      expect(result.scamCategory).toBe('OTP_CREDENTIAL_THEFT');
      expect(result.indicators.map((i) => i.type)).toContain('CREDENTIAL_THEFT');
    });

    it('detects Hinglish scam messages with urgency and rewards', () => {
      const hinglishMessage =
        'Badhai ho! Aapne jeeta hai cash prize of Rs 50000 on PhonePe. Turant claim karein: https://rewards-gift.top/claim';

      const result = LocalMessageHeuristics.analyze(hinglishMessage, 'SMS');

      expect(result.classification).toBe('SCAM');
      expect(result.riskLevel).toBe('HIGH');
      expect(result.extractedEntities.brandImpersonated).toBe('PhonePe');
      expect(result.indicators.map((i) => i.type)).toContain('FINANCIAL_LURE');
    });
  });

  describe('AIService End-to-End Pipeline & Provider Routing', () => {
    it('executes message analysis through AI Provider Router when configured, falling back to local heuristics if providers unavailable', async () => {
      const sbiMessage =
        'URGENT: Dear Customer, your SBI bank account will be blocked today due to incomplete KYC. Update immediately to avoid account suspension. Verify now: https://sbi-kyc-alert.example/verify Call customer care: +91 9876543210';

      const result = await AIService.analyzeMessage({
        messageText: sbiMessage,
        sourceType: 'SMS',
        userLanguage: 'en',
      });

      // Verification of Priority 5 & 6 requirements:
      // Even if AI backend is offline, verdict must NEVER be UNKNOWN with 0% score!
      expect(result.success).toBe(true);
      expect(result.classification).toBe('SCAM');
      expect(result.confidenceScore).toBeGreaterThan(0.8);
      expect(result.scamCategory).toBe('BANKING_KYC_PHISHING');
      expect(result.indicators.length).toBeGreaterThan(0);
      expect(result.diagnostics).toBeDefined();
      expect(result.diagnostics?.finalAnalysisStatus).toBeDefined();
    });

    it('records detailed developer diagnostics telemetry on execution', async () => {
      const testMsg = 'Test message for diagnostics validation';
      const result = await AIService.analyzeMessage({
        messageText: testMsg,
        sourceType: 'SMS',
      });

      expect(result.diagnostics).toBeDefined();
      expect(result.diagnostics?.requestId).toMatch(/^req_/);
      expect(result.diagnostics?.timestamp).toBeDefined();
      expect(result.diagnostics?.latencyMs).toBeGreaterThanOrEqual(0);
      expect(typeof result.diagnostics?.backendReachable).toBe('boolean');
    });
  });
});
