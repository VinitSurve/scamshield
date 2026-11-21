import { describe, it, expect } from 'vitest';
import { BotSecurity } from '../src/security';
import { ScannerClient } from '../src/scanner-client';

describe('ScamShield WhatsApp Bot & Security Engine', () => {
  describe('SSRF Protection for Media Downloads', () => {
    it('allows valid official Meta / WhatsApp CDN domains', () => {
      const validCdnUrl = 'https://lookaside.fbsbx.com/whatsapp_business/attachments/12345';
      expect(BotSecurity.isSafeMediaUrl(validCdnUrl)).toBe(true);

      const validCdnUrl2 = 'https://media.whatsapp.net/v/t62.7118-24/test.jpg';
      expect(BotSecurity.isSafeMediaUrl(validCdnUrl2)).toBe(true);
    });

    it('strictly blocks private network IP addresses and loopback hosts (SSRF prevention)', () => {
      expect(BotSecurity.isSafeMediaUrl('http://127.0.0.1:8080/secret')).toBe(false);
      expect(BotSecurity.isSafeMediaUrl('https://localhost/admin')).toBe(false);
      expect(BotSecurity.isSafeMediaUrl('https://169.254.169.254/latest/meta-data/')).toBe(false);
      expect(BotSecurity.isSafeMediaUrl('https://192.168.1.1/router')).toBe(false);
      expect(BotSecurity.isSafeMediaUrl('https://10.0.0.1/internal')).toBe(false);
    });

    it('strictly blocks untrusted external domains', () => {
      expect(BotSecurity.isSafeMediaUrl('https://attacker-c2-server.com/malware.exe')).toBe(false);
    });
  });

  describe('Message Threat Analysis & WhatsApp Reply Generation', () => {
    it('identifies banking KYC scam messages as CRITICAL threats with formatted advice', async () => {
      const incomingText = `
        Dear Customer, Your SBI account is blocked today!
        Complete KYC immediately: https://sbi-online-kyc-verification.top/login.php
        Helpline: 9876543210
      `;

      const result = await ScannerClient.scanMessage(incomingText, 'test_user_kyc');

      expect(result.verdict).toBe('CRITICAL');
      expect(result.category).toBe('FAKE_KYC');
      expect(result.riskScore).toBeGreaterThanOrEqual(90);
      expect(result.extractedUrls.length).toBe(1);
      expect(result.socialTactics.length).toBeGreaterThan(0);
      expect(result.formattedReply).toContain('SCAMSHIELD THREAT ALERT');
      expect(result.formattedReply).toContain('Do NOT click or open any links');
      expect(result.formattedReply).toContain('Reply *1* to trigger deeper investigation');
    }, 25000);

    it('identifies legitimate messages with clean status', async () => {
      const incomingText = 'Hey, are we still meeting for lunch at 1 PM today?';
      const result = await ScannerClient.scanMessage(incomingText, 'test_user_legit');

      expect(result.verdict).toBe('SAFE');
      expect(result.riskScore).toBeLessThan(10);
      expect(result.formattedReply).toContain('SAFE / NO KNOWN THREAT');
    }, 25000);

    it('processes user consent for deep investigation', async () => {
      const grantConsent = await ScannerClient.scanMessage('1', 'consent_user');
      expect(grantConsent.category).toBe('CONSENT_GRANTED');
      expect(grantConsent.formattedReply).toContain('Deep Threat Investigation Initiated');

      const skipConsent = await ScannerClient.scanMessage('2', 'consent_user');
      expect(skipConsent.category).toBe('CONSENT_SKIPPED');
      expect(skipConsent.formattedReply).toContain('investigation skipped');
    });
  });
});
