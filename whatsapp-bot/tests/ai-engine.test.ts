import { describe, it, expect } from 'vitest';
import { BackendAIEngine } from '../src/ai-engine.js';

describe('ScamShield Backend AI Threat Engine & Webhook Pipeline', () => {
  it('analyzes SBI KYC scam message deterministically via local heuristics when offline', () => {
    const sbiMsg =
      'URGENT: Dear Customer, your SBI bank account will be blocked today due to incomplete KYC. Update immediately to avoid account suspension. Verify now: https://sbi-kyc-alert.example/verify Call customer care: +91 9876543210';

    const res = BackendAIEngine.evaluateLocalHeuristics(sbiMsg, 'SMS');

    expect(res.success).toBe(true);
    expect(res.classification).toBe('SCAM');
    expect(res.riskLevel).toBe('HIGH');
    expect(res.confidenceScore).toBe(0.92);
    expect(res.scamCategory).toBe('BANKING_KYC_PHISHING');
    expect(res.extractedEntities.brandImpersonated).toBe('SBI');
    expect(res.extractedEntities.suspiciousUrls).toContain('https://sbi-kyc-alert.example/verify');
    expect(res.indicators.length).toBeGreaterThanOrEqual(4);
  });

  it('correctly classifies legitimate shopping messages as SAFE with zero false positives', () => {
    const legitMsg =
      'Your order has been shipped. You can track your delivery through the official shopping app. Expected delivery: 24 November. Thank you for shopping with us.';

    const res = BackendAIEngine.evaluateLocalHeuristics(legitMsg, 'SMS');

    expect(res.classification).toBe('SAFE');
    expect(res.riskLevel).toBe('LOW');
    expect(res.confidenceScore).toBe(0.05);
    expect(res.scamCategory).toBe('LEGITIMATE_COMMUNICATION');
    expect(res.indicators.length).toBe(0);
  });

  it('runs complete analyzeMessage pipeline returning full developer diagnostics', async () => {
    const testMsg = 'Urgent update: Your KYC is pending for your account. Click https://example.com';
    const res = await BackendAIEngine.analyzeMessage(testMsg, 'SMS');

    expect(res.diagnostics).toBeDefined();
    expect(res.diagnostics.requestId).toMatch(/^req_/);
    expect(res.diagnostics.timestamp).toBeDefined();
    expect(res.diagnostics.backendReachable).toBe(true);
    expect(res.diagnostics.finalAnalysisStatus).toBeDefined();
  }, 25000);
});
